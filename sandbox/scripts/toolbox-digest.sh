#!/usr/bin/env bash
# toolbox-digest — zero-LLM toolbox digest (docs/design.md §5.2).
#
# Emits COMPACT, VALID JSON (lowercase true/false) under 0.5KB: each category
# maps to the list of tools actually present. Deterministic for a given image.
set -euo pipefail

has() { command -v "$1" >/dev/null 2>&1; }
pyhas() { python3 -c "import $1" >/dev/null 2>&1; }

emit() { # category tool:present tool:present ...
  local cat="$1"; shift
  printf '"%s":[' "$cat"
  local first=1 name present
  for pair in "$@"; do
    name="${pair%%:*}"
    present="${pair##*:}"
    if [ "$present" = "yes" ]; then
      [ $first -eq 1 ] || printf ','
      printf '"%s"' "$name"
      first=0
    fi
  done
  printf ']'
}

py_present() { python3 -c "import $1" >/dev/null 2>&1 && echo yes || echo no; }
bin_present() { command -v "$1" >/dev/null 2>&1 && echo yes || echo no; }

pwn_tools="pwntools:$(py_present pwn) gdb:$(bin_present gdb) one_gadget:$(bin_present one_gadget) ropper:$(bin_present ropper) ROPgadget:$(bin_present ROPgadget)"
crypto_tools="sage:$(bin_present sage) pycryptodome:$(py_present Crypto) z3:$(py_present z3) gmpy2:$(py_present gmpy2) rsactftool:$(bin_present RsaCtfTool)"
web_tools="sqlmap:$(bin_present sqlmap) ffuf:$(bin_present ffuf) seclists:$([ -d /usr/share/seclists ] && echo yes || echo no) hashcat:$(bin_present hashcat) jwt_tool:$(bin_present jwt_tool)"
rev_tools="radare2:$(bin_present radare2) ghidra:$(bin_present analyzeHeadless) objdump:$(bin_present objdump) ltrace:$(bin_present ltrace) strace:$(bin_present strace)"
for_tools="binwalk:$(bin_present binwalk) volatility3:$(bin_present vol) stegseek:$(bin_present stegseek) exiftool:$(bin_present exiftool) tshark:$(bin_present tshark) sleuthkit:$(bin_present fls)"
gen_tools="python3:$(bin_present python3) gcc:$(bin_present gcc) git:$(bin_present git) jq:$(bin_present jq) curl:$(bin_present curl) nc:$(bin_present nc)"

printf '{'
emit pwn $pwn_tools; printf ','
emit crypto $crypto_tools; printf ','
emit web $web_tools; printf ','
emit rev $rev_tools; printf ','
emit forensics $for_tools; printf ','
emit general $gen_tools
printf '}\n'
