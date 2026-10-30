/**
 * Security & trust boundary (docs/design.md §7, ADR 0003).
 *
 * Untrusted is the default: challenge material is data, never instructions.
 * Kernel-only actions (flag write, complete, registry/guardrail edits) are
 * not reachable through the model surface; explicit attempts are blocked
 * with an audit event rather than a generic INVALID_REQUEST.
 */
import { Project } from './project.js';
import { KernelError } from './error.js';
import { hasUnparsableUrl, hostsInArgv } from './classify/classify.js';
import type { TargetSpec } from './types.js';

export function wrapUntrusted(text: string): string {
  return `<UNTRUSTED_DATA>\n${text}\n</UNTRUSTED_DATA>`;
}

export function wrapMemoryGuidance(text: string, provenance: string): string {
  return `<MEMORY_GUIDANCE provenance="${provenance}">\n${text}\n</MEMORY_GUIDANCE>`;
}

/** Ops the model must never reach; attempts are audited. */
const KERNEL_ONLY_OPS = new Set([
  'predicate.register',
  'contract.override',
  'guardrail.edit',
  'budget.raise',
  'allowedHosts.expand',
  'memory.addGlobal',
  'flag.write',
  'flag.txt',
  'registry.write',
]);

export function assertNotKernelOnly(project: Project | null, op: string): void {
  if (KERNEL_ONLY_OPS.has(op)) {
    project?.appendEvent('blocked.kernelOnly', 'hook', { op });
    throw new KernelError('SECURITY', `op ${op} is kernel-only; the model may request but not execute it`);
  }
}

/** Goal-contract scope check for run: every host referenced by argv must be
 *  allowed; any unparsable `://` token fails closed (review C1). This is a
 *  best-effort argv string match and can be bypassed; the scope constraint
 *  depends on the oracle and human review. */
function hostAllowed(allowedHosts: string[], host: string): boolean {
  const h = host.toLowerCase();
  // Local validation targets are always reachable from the host; blocking
  // loopback only pushes the agent to bash and loses the evidence chain.
  if (h === 'localhost' || h === '::1' || h.startsWith('127.')) return true;
  return allowedHosts.some((pattern) =>
    pattern === h || (pattern.startsWith('*.') && h.endsWith(pattern.slice(1))),
  );
}

/** Target metadata is checked even when the command text contains no URL
 *  (pwntools/script networking). */
export function checkTargetScope(project: Project, target: TargetSpec): void {
  const contract = project.goalContract();
  if (contract.allowedHosts.includes('*')) return;
  if (!hostAllowed(contract.allowedHosts, target.host)) {
    project.appendEvent('blocked.run', 'hook', { reason: 'target-not-allowed', target });
    throw new KernelError('SECURITY', `target host ${target.host} is not in allowedHosts`);
  }
}

export function checkRunScope(project: Project, argv: string[]): void {
  const contract = project.goalContract();
  if (contract.allowedHosts.includes('*')) return;
  for (const token of argv) {
    if (hasUnparsableUrl(token)) {
      project.appendEvent('blocked.run', 'hook', { reason: 'unparsable-url', argv: argv.slice(0, 8) });
      throw new KernelError('SECURITY', `token contains an unparsable URL, refusing to guess its target: ${token.slice(0, 80)}`);
    }
  }
  for (const host of hostsInArgv(argv)) {
    if (!hostAllowed(contract.allowedHosts, host)) {
      project.appendEvent('blocked.run', 'hook', { host, argv: argv.slice(0, 8) });
      throw new KernelError('SECURITY', `host ${host} is not in allowedHosts`);
    }
  }
}

/** Scan untrusted text for common prompt-injection payloads; report only —
 *  the boundary is structural (wrapping + kernel gates), not textual. */
const INJECTION_MARKERS = [
  'ignore previous instructions',
  'ignore all instructions',
  'disregard the above',
  'submit the flag',
  'write to flag.txt',
  'expand allowedhosts',
  'raise the budget',
];

export function scanInjection(text: string): string[] {
  const lower = text.toLowerCase();
  return INJECTION_MARKERS.filter((m) => lower.includes(m));
}
