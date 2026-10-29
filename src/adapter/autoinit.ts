/**
 * Pure auto-init detection for the pi extension.
 *
 * This module only reads the filesystem and returns an init spec. It never
 * writes `.ctf/`; the extension remains responsible for calling project.init
 * through the runtime protocol.
 */
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { parseTarget } from "../kernel/target.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = path.resolve(HERE, "..", "..");
export const DEFAULT_FLAG_FORMAT = "^(?:[A-Za-z][A-Za-z0-9_-]{0,31})\\{[^}\\r\\n]{1,512}\\}$";
const SOURCE_DIRS = ["src", "extensions", "docs", "fixtures", "sandbox", "scripts", "audit", "archive"];

export interface AutoInitOptions {
  env?: NodeJS.ProcessEnv;
  packageRoot?: string;
  homeDir?: string;
  dockerAvailable?: () => boolean;
  dockerImageAvailable?: (image: string) => boolean;
}

export interface ChallengeScan {
  hasElf: boolean;
  hasMarker: boolean;
}

export interface OracleInfo {
  ref: string;
  flag: string | null;
  target: Record<string, unknown> | null;
}

export function hasProject(root: string): boolean {
  return fs.existsSync(path.join(root, ".ctf", "project.json"));
}

export function readJsonFile(file: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    return parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

export function oracleLooksValid(file: string): boolean {
  const parsed = readJsonFile(file);
  const flag = typeof parsed?.flag === "string" ? parsed.flag.trim() : "";
  const sha = typeof parsed?.flagSha256 === "string" ? parsed.flagSha256 : "";
  return flag.length > 0 || /^[0-9a-f]{64}$/i.test(sha);
}

function pathInsideOrEqual(parent: string, child: string): boolean {
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function parseTargetLoose(value: unknown): Record<string, unknown> | null {
  try {
    return parseTarget(value) as Record<string, unknown> | null;
  } catch {
    return null;
  }
}

export function findOracle(root: string, env: NodeJS.ProcessEnv = process.env): OracleInfo {
  const parent = path.dirname(root);
  const candidates: string[] = [];
  if (env.PI4CTF_ORACLE) {
    const configured = env.PI4CTF_ORACLE;
    candidates.push(path.isAbsolute(configured) ? configured : path.resolve(root, configured));
  }
  // Prefer a challenge-specific oracle over a generic parent oracle.json.
  candidates.push(path.join(parent, `${path.basename(root)}-oracle.json`));
  candidates.push(path.join(parent, "oracle.json"));
  for (const abs of candidates) {
    if (!fs.existsSync(abs)) continue;
    if (!pathInsideOrEqual(parent, abs) || pathInsideOrEqual(root, abs)) continue;
    const parsed = readJsonFile(abs);
    const flag = typeof parsed?.flag === "string" ? parsed.flag : null;
    const sha = typeof parsed?.flagSha256 === "string" ? parsed.flagSha256 : null;
    if (flag || (sha && /^[0-9a-f]{64}$/i.test(sha))) {
      const target = parseTargetLoose(parsed?.target)
        ?? (typeof parsed?.host === "string"
          ? parseTargetLoose({ host: parsed.host, port: parsed.port, instanceId: parsed.instanceId })
          : null);
      return { ref: path.relative(root, abs).split(path.sep).join("/"), flag, target };
    }
  }
  return { ref: "../oracle.json", flag: null, target: null };
}

function inferFlagFormat(flag: string | null): string {
  if (flag) {
    const m = /^([A-Za-z][A-Za-z0-9_]*)\{[^}]+\}$/.exec(flag);
    if (m?.[1]) return `${m[1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\{[^}]+\\}`;
  }
  return DEFAULT_FLAG_FORMAT;
}

function isElfFile(file: string): boolean {
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.size < 4) return false;
    const fd = fs.openSync(file, "r");
    try {
      const head = Buffer.alloc(4);
      fs.readSync(fd, head, 0, 4, 0);
      return head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return false;
  }
}

export function scanChallenge(root: string, maxDepth = 2): ChallengeScan {
  let hasElf = false;
  let hasMarker = false;
  const visit = (dir: string, depth: number) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (ent.name === ".ctf" || ent.name === ".git" || ent.name === "node_modules") continue;
      const abs = path.join(dir, ent.name);
      if (ent.isSymbolicLink()) continue;
      if (ent.isDirectory()) {
        if (depth < maxDepth) visit(abs, depth + 1);
        continue;
      }
      if (!ent.isFile()) continue;
      const name = ent.name.toLowerCase();
      if (isElfFile(abs)) hasElf = true;
      if (
        /\.(?:elf|pwn|apk|pcap|zip|tar|tgz|7z|rar|img|qcow2|vmdk|exe|dll|so|bin|jar|class|war|jsp|jspx|java)$/i.test(name) ||
        /^(?:pwn|chall|challenge|vuln|target|baby|easy|hard|flag|oracle|task|description)(?:\.|$)/i.test(name) ||
        name === "ctf.json"
      ) {
        hasMarker = true;
      }
    }
  };
  visit(root, 0);
  const segments = root.split(/[\\/]/).map((s) => s.toLowerCase());
  if (segments.some((s) => s === "challenges" || s === "ctf" || s === "ctfs")) hasMarker = true;
  return { hasElf, hasMarker };
}

export function shouldAutoInit(root: string, opts: AutoInitOptions = {}): boolean {
  const env = opts.env ?? process.env;
  if (env.PI4CTF_AUTO_INIT === "0") return false;
  const abs = path.resolve(root);
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(abs, { withFileTypes: true });
  } catch {
    return false;
  }
  if (entries.length === 0) return false;
  const packageRoot = opts.packageRoot ?? PACKAGE_ROOT;
  const home = opts.homeDir ?? os.homedir();
  if (abs === path.resolve(home) || abs === packageRoot || path.dirname(abs) === abs) return false;
  if (["challenges", "ctfs"].includes(path.basename(abs).toLowerCase())) return false;
  // Never auto-init the pi4ctf source tree itself; its challenges/ children
  // are still allowed because they carry challenge material.
  if (SOURCE_DIRS.some((d) => abs === path.join(packageRoot, d) || abs.startsWith(path.join(packageRoot, d) + path.sep))) {
    return false;
  }
  if (["1", "true", "always"].includes((env.PI4CTF_AUTO_INIT ?? "").toLowerCase())) return true;
  const scan = scanChallenge(abs);
  return scan.hasMarker || scan.hasElf;
}

export function autoInitSpec(root: string, opts: AutoInitOptions = {}): Record<string, unknown> {
  const env = opts.env ?? process.env;
  const oracle = findOracle(root, env);
  const scan = scanChallenge(root);
  const envTarget = parseTargetLoose(env.PI4CTF_TARGET);
  const envInstance = env.PI4CTF_INSTANCE_ID;
  const target = envTarget
    ? { ...envTarget, ...(envTarget.instanceId || !envInstance ? {} : { instanceId: envInstance }) }
    : oracle.target
      ? { ...oracle.target, ...(oracle.target.instanceId || !envInstance ? {} : { instanceId: envInstance }) }
      : undefined;
  const envBackend = env.PI4CTF_BACKEND;
  const dockerImage = env.PI4CTF_DOCKER_IMAGE ?? env.PI4CTF_PWN_IMAGE;
  const dockerUp = opts.dockerAvailable
    ? opts.dockerAvailable()
    : (() => {
        try {
          return spawnSync("docker", ["--version"], { stdio: "ignore", timeout: 2000, windowsHide: true }).status === 0;
        } catch {
          return false;
        }
      })();
  const imageUp = Boolean(dockerImage) && dockerUp && (opts.dockerImageAvailable
    ? opts.dockerImageAvailable(dockerImage as string)
    : (() => {
        try {
          return spawnSync("docker", ["image", "inspect", dockerImage as string], { stdio: "ignore", timeout: 3000, windowsHide: true }).status === 0;
        } catch {
          return false;
        }
      })());
  const backend = envBackend === "host"
    ? "host"
    : envBackend === "docker" && dockerImage
      ? "docker"
      : envBackend === "docker"
        ? "host"
        : scan.hasElf && imageUp
          ? "docker"
          : "host";
  const id = path.basename(root) || "ctf";
  return {
    id,
    title: id,
    goal: "solve the challenge and validate the flag",
    origin: "auto-init",
    category: scan.hasElf ? "pwn" : "misc",
    flagFormat: inferFlagFormat(oracle.flag),
    target,
    backend,
    dockerImage: backend === "docker" && dockerImage ? dockerImage : undefined,
    oracleRef: oracle.ref,
    allowedHosts: ["*"],
  };
}
