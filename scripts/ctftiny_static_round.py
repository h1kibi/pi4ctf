#!/usr/bin/env python3
"""Run the static CTFTiny slice with the installed pi4ctf + deepseek-flash.

This is a black-box-ish harness:
- copies only the challenge-declared `files` (never challenge.json/flag/readme/solver)
- keeps the oracle outside the workspace
- runs pi with only ctf/run/read tools
- scores by the kernel's accepted .ctf/flag.txt

Usage:
  python scripts/ctftiny_static_round.py [--limit N] [--only id,id]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = Path("C:/Projects/Agent-projects/ctf-benchmark/CTFTiny")
META = BENCH / "ctftiny.json"
WORK = ROOT / "challenges" / "ctftiny-static"
RESULTS = ROOT / "challenges" / "ctftiny-static-results"
ORACLES = WORK / ".oracles"
MODEL = "deepseek/deepseek-flash"
TIMEOUT_S = 240
CATEGORIES = {"crypto", "rev", "forensics", "misc"}


def load_challenges() -> list[dict]:
    data = json.loads(META.read_text(encoding="utf-8"))
    out = []
    for key, item in data.items():
        if item.get("category") not in CATEGORIES:
            continue
        base = BENCH / item["path"]
        try:
            meta = json.loads((base / "challenge.json").read_text(encoding="utf-8"))
        except OSError:
            continue
        if meta.get("compose") or not meta.get("files"):
            continue
        out.append({"key": key, "item": item, "base": base, "meta": meta})
    return out


def copy_inputs(ch: dict, dest: Path) -> list[str]:
    copied = []
    for rel in ch["meta"]["files"]:
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
    prefix = flag.split("{", 1)[0]
    return re.escape(prefix) + r"\{[^}]+\}"


def init_project(ch: dict, dest: Path, oracle: Path) -> None:
    flag = str(ch["meta"]["flag"])
    payload = {
        "id": ch["key"],
        "title": ch["meta"].get("name", ch["key"]),
        "goal": "solve the challenge and submit the flag",
        "category": ch["item"]["category"],
        "flagFormat": flag_pattern(flag),
        "backend": "host",
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


def run_one(ch: dict, model: str, timeout_s: int) -> dict:
    key = ch["key"]
    dest = WORK / key
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    copied = copy_inputs(ch, dest)
    oracle = ORACLES / f"{key}.json"
    oracle.parent.mkdir(parents=True, exist_ok=True)
    oracle.write_text(json.dumps({"flag": ch["meta"]["flag"]}), encoding="utf-8")
    (dest / "README.md").write_text(
        "# " + ch["meta"].get("name", key) + "\n\n"
        + str(ch["meta"].get("description", "")) + "\n\n"
        + "Files: " + ", ".join(copied) + "\n\n"
        + "Flag format: " + flag_pattern(str(ch["meta"]["flag"])) + "\n",
        encoding="utf-8",
    )
    init_project(ch, dest, oracle)
    prompt = (
        "Solve this static CTF challenge. Use the ctf skill and the pi4ctf tools. "
        "Read README.md and the provided files. Use run for commands, claim for "
        "quote-backed evidence, and flag for submission. Do not access parent "
        "directories, .ctf, or oracle files. Work autonomously. If you cannot "
        "solve it, report the exact blocker."
    )
    started = time.time()
    try:
        proc = subprocess.run(
            ["pi", "--no-session", "--model", model, "--thinking", "high",
             "--tools", "run,session,claim,flag,read,find,grep,ls",
             "-p", prompt],
            cwd=str(dest), text=True, capture_output=True, encoding="utf-8",
            errors="replace", timeout=timeout_s,
        )
        timed_out = False
        out = proc.stdout
        err = proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        err = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
    flag_txt = dest / ".ctf" / "flag.txt"
    accepted = flag_txt.exists() and flag_txt.read_text(encoding="utf-8").strip() == ch["meta"]["flag"]
    record = {
        "key": key,
        "category": ch["item"]["category"],
        "flag": ch["meta"]["flag"],
        "accepted": accepted,
        "timed_out": timed_out,
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
    print(f"challenges={len(challenges)} model={args.model} timeout={args.timeout}s", flush=True)
    records = []
    for i, ch in enumerate(challenges, 1):
        print(f"[{i}/{len(challenges)}] {ch['key']} ...", flush=True)
        try:
            rec = run_one(ch, args.model, args.timeout)
        except Exception as exc:
            rec = {"key": ch["key"], "category": ch["item"]["category"], "accepted": False,
                   "error": str(exc), "duration_s": 0}
            (RESULTS / f"{ch['key']}.json").write_text(json.dumps(rec, indent=2), encoding="utf-8")
        records.append(rec)
        print(f"  accepted={rec.get('accepted')} time={rec.get('duration_s')}s", flush=True)
    solved = sum(1 for r in records if r.get("accepted"))
    print(f"SCORE {solved}/{len(records)}")
    (RESULTS / "score.json").write_text(json.dumps({
        "model": args.model,
        "total": len(records),
        "solved": solved,
        "records": records,
    }, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
