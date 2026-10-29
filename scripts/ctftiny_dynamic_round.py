#!/usr/bin/env python3
"""Run the dynamic CTFTiny slice with prebuilt Docker targets and deepseek-flash.

Assumes each challenge's docker-compose.yml names an image containing the
challenge flag (the CTFTiny convention). The solver runs in pwnlab and reaches
the target through host.docker.internal.

Usage:
  python scripts/ctftiny_dynamic_round.py [--limit N] [--only id,id]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = Path("C:/Projects/Agent-projects/ctf-benchmark/CTFTiny")
META = BENCH / "ctftiny.json"
WORK = ROOT / "challenges" / "ctftiny-dynamic"
RESULTS = ROOT / "challenges" / "ctftiny-dynamic-results"
ORACLES = WORK / ".oracles"
MODEL = "deepseek/deepseek-flash"
PWN_IMAGE = "pwnlab:general-debian12"
TIMEOUT_S = 300
HOST_PORT_BASE = 19000


def load_challenges() -> list[dict]:
    data = json.loads(META.read_text(encoding="utf-8"))
    out = []
    for key, item in data.items():
        base = BENCH / item["path"]
        if not base.exists():
            base = BENCH / item["path"].replace("?", "\uf03f")
        try:
            meta = json.loads((base / "challenge.json").read_text(encoding="utf-8"))
        except OSError:
            continue
        if not meta.get("compose"):
            continue
        port = meta.get("internal_port") or meta.get("port")
        if not port:
            continue
        compose = (base / "docker-compose.yml").read_text(encoding="utf-8")
        m = re.search(r"^\s*image:\s*['\"]?([^'\"\s]+)", compose, re.MULTILINE)
        if not m:
            continue
        out.append({"key": key, "item": item, "base": base, "meta": meta, "image": m.group(1), "port": port})
    return out


def copy_inputs(ch: dict, dest: Path) -> list[str]:
    copied = []
    for rel in ch["meta"].get("files") or []:
        rel = rel.removeprefix("./")
        src = ch["base"] / rel
        if not src.exists():
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, target, dirs_exist_ok=True)
        else:
            shutil.copy2(src, target)
        copied.append(rel)
    return copied


def flag_pattern(flag: str) -> str:
    return re.escape(flag.split("{", 1)[0]) + r"\{[^}]+\}"


def docker(*args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], text=True, capture_output=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def ensure_image(image: str) -> None:
    inspect = docker("image", "inspect", image, timeout=30)
    if inspect.returncode != 0:
        pull = docker("pull", image, timeout=600)
        if pull.returncode != 0:
            raise RuntimeError(f"pull failed: {pull.stderr[-500:]}")


def start_target(ch: dict, host_port: int) -> str:
    name = f"ctf-{re.sub(r'[^a-z0-9]+', '-', ch['key'].lower())}-target"
    docker("rm", "-f", name, timeout=30)
    run = docker("run", "-d", "--name", name, "-p",
                 f"127.0.0.1:{host_port}:{ch['port']}", ch["image"],
                 timeout=180)
    if run.returncode != 0:
        raise RuntimeError(f"run failed: {run.stderr[-500:]}")
    time.sleep(1.5)
    ps = docker("ps", "--filter", f"name={name}", "--format", "{{.Status}}", timeout=30)
    if ps.returncode != 0 or not ps.stdout.strip():
        logs = docker("logs", "--tail", "30", name, timeout=30)
        raise RuntimeError(f"target not running: {ps.stderr or logs.stderr or logs.stdout}")
    return name


def init_project(ch: dict, dest: Path, oracle: Path) -> None:
    payload = {
        "id": ch["key"],
        "title": ch["meta"].get("name", ch["key"]),
        "goal": "exploit the target and submit the flag",
        "category": ch["item"]["category"],
        "flagFormat": flag_pattern(str(ch["meta"]["flag"])),
        "backend": "docker",
        "dockerImage": PWN_IMAGE,
        "oracleRef": os.path.relpath(oracle, dest),
        "allowedHosts": ["*"],
    }
    proc = subprocess.run(
        ["node", str(ROOT / "dist" / "rt.js"), "--op", "project.init",
         "--root", str(dest), "--input", json.dumps(payload)],
        cwd=str(dest), text=True, capture_output=True, encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"project.init failed: {proc.stdout} {proc.stderr}")


def run_one(ch: dict, host_port: int, model: str, timeout_s: int) -> dict:
    key = ch["key"]
    dest = WORK / key
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    copied = copy_inputs(ch, dest)
    oracle = ORACLES / f"{key}.json"
    oracle.parent.mkdir(parents=True, exist_ok=True)
    oracle.write_text(json.dumps({"flag": ch["meta"]["flag"]}), encoding="utf-8")
    target = f"http://host.docker.internal:{host_port}/" if ch["item"]["category"] == "web" else f"host.docker.internal:{host_port}"
    (dest / "README.md").write_text(
        "# " + ch["meta"].get("name", key) + "\n\n"
        + str(ch["meta"].get("description", "")) + "\n\n"
        + f"Target: `{target}`\n\n"
        + "Files: " + ", ".join(copied) + "\n\n"
        + "Flag format: " + flag_pattern(str(ch["meta"]["flag"])) + "\n",
        encoding="utf-8",
    )
    init_project(ch, dest, oracle)
    started = time.time()
    target_name = None
    infra_error = None
    try:
        ensure_image(ch["image"])
        target_name = start_target(ch, host_port)
        prompt = (
            f"Solve this dynamic CTF challenge. Target: {target}. "
            "Use the ctf skill and pi4ctf tools. Use run/session inside the pwn Docker environment, "
            "claim with quote-backed evidence, then flag. Do not use bash. Do not access parent "
            "directories, .ctf, or oracle files. Work autonomously; if blocked, report exact evidence."
        )
        proc = subprocess.run(
            ["pi", "--no-session", "--model", model, "--thinking", "high",
             "--tools", "run,session,claim,flag,read,find,grep,ls", "-p", prompt],
            cwd=str(dest), text=True, capture_output=True, encoding="utf-8",
            errors="replace", timeout=timeout_s,
        )
        timed_out = False
        out, err = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        err = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
    except Exception as exc:
        timed_out = False
        out, err = "", str(exc)
        infra_error = str(exc)
    finally:
        if target_name:
            docker("rm", "-f", target_name, timeout=30)
    flag_txt = dest / ".ctf" / "flag.txt"
    accepted = flag_txt.exists() and flag_txt.read_text(encoding="utf-8").strip() == ch["meta"]["flag"]
    record = {
        "key": key,
        "category": ch["item"]["category"],
        "image": ch["image"],
        "target": target,
        "flag": ch["meta"]["flag"],
        "accepted": accepted,
        "timed_out": timed_out,
        "infra_error": infra_error,
        "duration_s": round(time.time() - started, 1),
        "files": copied,
        "stdout": out[-4000:],
        "stderr": err[-2000:],
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"{key}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    (RESULTS / f"{key}.log").write_text(out + "\n--- STDERR ---\n" + err, encoding="utf-8")
    return record


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--only", default="")
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--timeout", type=int, default=TIMEOUT_S)
    args = ap.parse_args()
    challenges = load_challenges()
    if args.only:
        wanted = {x.strip() for x in args.only.split(",") if x.strip()}
        challenges = [c for c in challenges if c["key"] in wanted]
    if args.limit:
        challenges = challenges[: args.limit]
    RESULTS.mkdir(parents=True, exist_ok=True)
    print(f"dynamic challenges={len(challenges)} model={args.model} timeout={args.timeout}s", flush=True)
    records = []
    for i, ch in enumerate(challenges):
        host_port = HOST_PORT_BASE + i
        print(f"[{i+1}/{len(challenges)}] {ch['key']} port={host_port} ...", flush=True)
        try:
            rec = run_one(ch, host_port, args.model, args.timeout)
        except Exception as exc:
            rec = {"key": ch["key"], "category": ch["item"]["category"], "accepted": False,
                   "timed_out": False, "infra_error": str(exc), "duration_s": 0}
            (RESULTS / f"{ch['key']}.json").write_text(json.dumps(rec, indent=2), encoding="utf-8")
        records.append(rec)
        print(f"  accepted={rec.get('accepted')} infra={bool(rec.get('infra_error'))} time={rec.get('duration_s')}s", flush=True)
    solved = sum(1 for r in records if r.get("accepted"))
    print(f"DYNAMIC_SCORE {solved}/{len(records)}")
    (RESULTS / "score.json").write_text(json.dumps({
        "model": args.model, "total": len(records), "solved": solved, "records": records,
    }, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
