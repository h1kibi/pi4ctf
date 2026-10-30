/**
 * Flag: four-layer validation (docs/design.md §4.5, kernel-design §8).
 * format -> provenance -> evidence -> oracle, plus dedupe. Any layer failing
 * rejects; only all-pass writes .ctf/flag.txt. `flag` is a request, never a
 * write; the model cannot self-certify.
 */
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { appendJsonl, atomicWriteFile } from '../fsutil.js';
import { KernelError } from '../error.js';
import { Ledger } from '../ledger/store.js';
import { Project } from '../project.js';
import type { FlagLayers, FlagRecord, TargetSpec } from '../types.js';
import { DEFAULT_FLAG_FORMAT } from './format.js';
import { sameTarget, targetRef } from '../target.js';
import { oracleBindingError, type OracleFile } from '../oracle.js';

const PLACEHOLDER_RE = /^(?:[A-Za-z][A-Za-z0-9_-]{0,31})\{(?:\.\.\.|x+|X+|\*+|<[^>]*>|\$\{[^}]*\})\}$/i;

interface OracleCheck {
  exact: boolean;
  unavailable: boolean;
  detail: string | null;
}

function inspectOracle(project: Project, value: string, file: ReturnType<Project['file']>): OracleCheck {
  const oraclePath = path.resolve(project.root, file.oracle.ref);
  if (!file.oracleHash) {
    return { exact: false, unavailable: true, detail: 'oracle was not pinned; place a target-bound oracle outside the workspace then run /ctf configure (refusing self-generated oracle)' };
  }
  if (!fs.existsSync(oraclePath)) {
    return { exact: false, unavailable: true, detail: `oracle file missing: ${file.oracle.ref}` };
  }
  const raw = fs.readFileSync(oraclePath);
  const currentHash = crypto.createHash('sha256').update(raw).digest('hex');
  if (currentHash !== file.oracleHash) {
    return { exact: false, unavailable: false, detail: 'oracle changed after project.init; refusing self-generated oracle' };
  }
  let oracle: OracleFile;
  try {
    oracle = JSON.parse(raw.toString('utf8')) as OracleFile;
  } catch {
    return { exact: false, unavailable: true, detail: 'oracle is not valid JSON' };
  }
  const sha = crypto.createHash('sha256').update(value).digest('hex');
  const exact =
    (typeof oracle.flag === 'string' && oracle.flag === value) ||
    (typeof oracle.flagSha256 === 'string' && oracle.flagSha256 === sha);

  // Instance binding is shared with project.init/configure so the same
  // mismatch fails fast instead of surfacing only at flag submission.
  const projectTarget = file.target ?? null;
  try {
    const bindingError = oracleBindingError(oracle, projectTarget);
    if (bindingError) return { exact: false, unavailable: true, detail: bindingError };
  } catch {
    return { exact: false, unavailable: true, detail: 'oracle target metadata is invalid' };
  }
  if (!exact) return { exact: false, unavailable: false, detail: 'oracle rejected the flag value' };
  return { exact: true, unavailable: false, detail: null };
}


function artifactIsSynthetic(project: Project, ref: string): boolean {
  const outcomesDir = path.join(project.ctfDir, 'outcomes');
  if (!fs.existsSync(outcomesDir)) return false;
  for (const name of fs.readdirSync(outcomesDir)) {
    if (!name.endsWith('.json')) continue;
    const o = JSON.parse(fs.readFileSync(path.join(outcomesDir, name), 'utf8')) as {
      id?: string;
      synthetic?: boolean;
      stdout?: { rawRef?: string; shapedRef?: string };
      stderr?: { rawRef?: string; shapedRef?: string };
    };
    if (!o.synthetic) continue;
    if ([o.stdout?.rawRef, o.stdout?.shapedRef, o.stderr?.rawRef, o.stderr?.shapedRef].includes(ref)) {
      return true;
    }
    if (!o.id) continue;
    const itemsDir = path.join(project.ctfDir, 'items');
    if (!fs.existsSync(itemsDir)) continue;
    for (const itemName of fs.readdirSync(itemsDir)) {
      if (!itemName.startsWith(`${o.id}.`) || !itemName.endsWith('.json')) continue;
      const item = JSON.parse(fs.readFileSync(path.join(itemsDir, itemName), 'utf8')) as {
        stdout?: { rawRef?: string; shapedRef?: string };
        stderr?: { rawRef?: string; shapedRef?: string };
      };
      if ([item.stdout?.rawRef, item.stdout?.shapedRef, item.stderr?.rawRef, item.stderr?.shapedRef].includes(ref)) {
        return true;
      }
    }
  }
  return false;
}

function artifactFromCurrentTarget(project: Project, ref: string, target: TargetSpec | null): boolean {
  if (!target) return true;
  const wanted = targetRef(target);
  const outcomesDir = path.join(project.ctfDir, 'outcomes');
  if (!fs.existsSync(outcomesDir)) return false;
  const allowed = new Set<string>();
  for (const name of fs.readdirSync(outcomesDir)) {
    if (!name.endsWith('.json')) continue;
    try {
      const o = JSON.parse(fs.readFileSync(path.join(outcomesDir, name), 'utf8')) as {
        id?: string;
        target?: string | null;
        instanceId?: string | null;
        stdout?: { rawRef?: string; shapedRef?: string };
        stderr?: { rawRef?: string; shapedRef?: string };
      };
      const same = o.target === wanted &&
        (target.instanceId === undefined || (o.instanceId ?? '') === target.instanceId);
      if (!same) continue;
      for (const stream of [o.stdout, o.stderr]) {
        if (stream?.rawRef) allowed.add(stream.rawRef);
        if (stream?.shapedRef) allowed.add(stream.shapedRef);
      }
      if (!o.id) continue;
      const itemsDir = path.join(project.ctfDir, 'items');
      if (fs.existsSync(itemsDir)) {
        for (const itemName of fs.readdirSync(itemsDir)) {
          if (!itemName.startsWith(`${o.id}.`) || !itemName.endsWith('.json')) continue;
          const item = JSON.parse(fs.readFileSync(path.join(itemsDir, itemName), 'utf8')) as {
            stdout?: { rawRef?: string; shapedRef?: string };
            stderr?: { rawRef?: string; shapedRef?: string };
          };
          for (const stream of [item.stdout, item.stderr]) {
            if (stream?.rawRef) allowed.add(stream.rawRef);
            if (stream?.shapedRef) allowed.add(stream.shapedRef);
          }
        }
      }
    } catch {
      // skip corrupt outcomes; doctor reports them
    }
  }
  return allowed.has(ref);
}

export interface FlagVerdict {
  status: 'accepted' | 'unverified' | 'rejected';
  layers: FlagLayers;
  detail: Record<string, string | null>;
  record: FlagRecord;
}

export function submitFlag(
  project: Project,
  ledger: Ledger,
  input: { value: string; sourceRef?: string | null; evidenceRefs?: string[] },
): FlagVerdict {
  const file = project.file();
  const value = input.value.trim();
  if (value.length === 0) throw new KernelError('INVALID_REQUEST', 'flag value is empty');
  if (value.length > 1024) throw new KernelError('LIMIT', 'flag value exceeds 1KB');
  if ((input.evidenceRefs ?? []).length > 16) throw new KernelError('LIMIT', 'too many evidenceRefs');
  const layers: FlagLayers = { format: false, provenance: false, evidence: false, oracle: false, dedupe: false };
  const detail: Record<string, string | null> = {
    format: null,
    provenance: null,
    evidence: null,
    oracle: null,
    dedupe: null,
  };
  const currentTarget = file.target ?? null;

  const oracle = inspectOracle(project, value, file);

  // Layer 1: format ---------------------------------------------------------
  try {
    const re = new RegExp(file.flagFormat);
    const placeholder = PLACEHOLDER_RE.test(value);
    const formatOk = re.test(value) && !placeholder;
    // The generic default is a guardrail, not a ground-truth claim. If the
    // oracle is pinned and exact, a non-`flag{}` prefix must not be killed by
    // our guess. Explicit custom formats remain strict. Placeholders are
    // always rejected, even if an oracle somehow contains one.
    layers.format = !placeholder && (formatOk || (oracle.exact && file.flagFormat === DEFAULT_FLAG_FORMAT));
    if (!layers.format) detail.format = `value does not match flagFormat ${file.flagFormat}`;
  } catch {
    detail.format = 'project flagFormat is not a valid regex';
  }

  // Layer 2: provenance — flag must appear in a stored artifact -------------
  let provenanceRef: string | null = null;
  if (layers.format) {
    const artifactsDir = path.join(project.ctfDir, 'artifacts');
    if (fs.existsSync(artifactsDir)) {
      outer: for (const name of fs.readdirSync(artifactsDir).sort()) {
        if (!name.endsWith('.log')) continue;
        const ref = `artifacts/${name}`;
        if (!artifactFromCurrentTarget(project, ref, file.target ?? null)) continue;
        const p = path.join(artifactsDir, name);
        const buf = fs.readFileSync(p);
        if (buf.includes(Buffer.from(value, 'utf8'))) {
          provenanceRef = ref;
          break outer;
        }
      }
    }
    layers.provenance = provenanceRef !== null;
    if (!layers.provenance) {
      detail.provenance = file.target
        ? 'flag value not found in an artifact from the current target'
        : 'flag value not found in any stored artifact';
    }
  }

  // Layer 3: evidence — linked verified Fact or accepted claim ---------------
  let syntheticEvidence = false;
  if (layers.provenance) {
    const allFacts = ledger.listFacts();
    const allClaims = ledger.listClaims().filter((c) => c.state === 'accepted');
    const targetOk = (target?: string | null, instanceId?: string | null): boolean => {
      if (!currentTarget) return true;
      if (!target || target !== targetRef(currentTarget)) return false;
      return (instanceId ?? '') === (currentTarget.instanceId ?? '');
    };
    const facts = allFacts.filter((f) => f.synthetic !== true && targetOk(f.target, f.instanceId));
    const claims = allClaims.filter((c) => c.synthetic !== true && targetOk(c.target, c.instanceId));
    const refs = input.evidenceRefs ?? [];
    const syntheticRef = refs.some((r) =>
      allFacts.some((f) => f.id === r && f.synthetic === true) ||
      allClaims.some((c) => c.id === r && c.synthetic === true),
    );
    layers.evidence = refs.some(
      (r) => facts.some((f) => f.id === r) || claims.some((c) => c.id === r),
    );
    syntheticEvidence = syntheticRef || (provenanceRef ? artifactIsSynthetic(project, provenanceRef) : false);
    if (syntheticEvidence) {
      layers.evidence = false;
      detail.evidence = 'synthetic evidence cannot validate a real flag; use a separate dry-run project';
    } else if (!layers.evidence) {
      detail.evidence = currentTarget
        ? 'no verified Fact/accepted claim from the current target/instance linked via evidenceRefs'
        : 'no verified Fact or accepted claim linked via evidenceRefs';
    }
  }

  // Layer 4: oracle — local ground truth outside the workspace ---------------
  // The oracle must be present and pinned at project.init. A file created or
  // modified after init could be the model's own answer, which is not
  // independent ground truth.
  if (layers.evidence) {
    layers.oracle = oracle.exact;
    if (!oracle.exact) detail.oracle = oracle.detail;
  }

  // Layer 5 (dedupe): same value already accepted or rejected  ---------------
  const ledgerPath = path.join(project.ctfDir, 'flags.jsonl');
  const outcome = project.withLock(() => {
    const priorLines = fs.existsSync(ledgerPath)
      ? fs.readFileSync(ledgerPath, 'utf8').trim().split('\n').filter(Boolean)
      : [];
    const prior = priorLines.map((l) => JSON.parse(l) as FlagRecord);
    const sameContext = (r: FlagRecord): boolean => {
      const formatSame = r.flagFormat !== undefined && r.flagFormat === file.flagFormat;
      const oracleSame = r.oracleHash !== undefined && r.oracleHash === file.oracleHash;
      const targetSame = r.target !== undefined && sameTarget(r.target, currentTarget) &&
        (r.instanceId ?? '') === (currentTarget?.instanceId ?? '');
      return formatSame && oracleSame && targetSame;
    };
    const sameRecords = prior.filter((r) => r.flag === value);
    const sameAccepted = sameRecords.some((r) => r.status === 'accepted' && sameContext(r));
    // A rejection caused by missing provenance/evidence/target/oracle is
    // incomplete, not definitive. A wrong explicit format or an oracle
    // rejection is definitive only for the same format+oracle+target context;
    // after case.configure or an instance switch, retry is allowed.
    const definitiveReject = sameRecords.some((r) =>
      r.status === 'rejected' && sameContext(r) && (
        r.detail.format !== null ||
        (r.detail.oracle !== null &&
          !r.detail.oracle.startsWith('oracle file missing') &&
          !r.detail.oracle.startsWith('oracle was not pinned'))
      ),
    );
    layers.dedupe = !sameAccepted && !definitiveReject;
    if (sameAccepted) detail.dedupe = 'same flag value already accepted';
    else if (definitiveReject) detail.dedupe = 'same flag value definitively rejected (format/oracle)';
    else if (sameRecords.some((r) => r.status === 'rejected')) {
      detail.dedupe = 'retry allowed: previous rejection was incomplete or context changed';
    }

    const accepted = layers.format && layers.provenance && layers.evidence && layers.oracle && layers.dedupe;
    const unverified = !accepted && layers.format && layers.provenance && layers.evidence && layers.dedupe && oracle.unavailable;
    const status: 'accepted' | 'unverified' | 'rejected' = accepted ? 'accepted' : unverified ? 'unverified' : 'rejected';
    const record: FlagRecord = {
      flag: value,
      flagSha256: crypto.createHash('sha256').update(value).digest('hex'),
      source: { kind: provenanceRef ? 'artifact' : 'model', ref: provenanceRef ?? input.sourceRef ?? null },
      status,
      layers,
      detail,
      oracle: file.oracle.type,
      flagFormat: file.flagFormat,
      oracleHash: file.oracleHash,
      target: currentTarget,
      instanceId: currentTarget?.instanceId ?? null,
      synthetic: syntheticEvidence,
      ts: Date.now(),
    };
    appendJsonl(ledgerPath, record);
    project.appendEvent(accepted ? 'flag.accepted' : unverified ? 'flag.unverified' : 'flag.rejected', 'model', {
      flagSha256: record.flagSha256,
      layers,
    });
    return { accepted, status, record };
  });

  if (outcome.accepted) {
    atomicWriteFile(path.join(project.ctfDir, 'flag.txt'), value + '\n');
  }
  return { status: outcome.status, layers, detail, record: outcome.record };
}

export function readAcceptedFlag(project: Project): string | null {
  const p = path.join(project.ctfDir, 'flag.txt');
  if (!fs.existsSync(p)) return null;
  // A flag accepted for an old target/instance must not be presented as the
  // current case's accepted flag.
  if (!project.flagAccepted()) return null;
  return fs.readFileSync(p, 'utf8').trim();
}
