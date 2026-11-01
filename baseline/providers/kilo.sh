#!/bin/bash
# Provider for `baseline.py record --provider cmd`: a free Kilo-hosted model (KILO_MODEL, default NVIDIA Nemotron 3 Ultra),
# tools denied. Prompt on stdin, reply on stdout.
M=${KILO_MODEL:-kilo/nvidia/nemotron-3-ultra-550b-a55b:free}; P=$(cat); D=$(mktemp -d)
printf '%s' '{"permission":{"*":"deny"}}' > "$D/kilo.json"
cd "$D" && kilo run --agent ask --format json -m "$M" "You have no tools; answer in plain text only. $P" < /dev/null 2>/dev/null |
  python3 -c '
import json, sys
for line in sys.stdin:
    try: e = json.loads(line)
    except ValueError: continue
    p = e.get("part") or {}
    if e.get("type") == "text" and p.get("text"): sys.stdout.write(p["text"])'
rm -rf "$D"
