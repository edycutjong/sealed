#!/usr/bin/env python3
"""Provider for `baseline.py record --provider cmd`: Muse (Meta Model API, Standard tier). Prompt on stdin, reply on stdout.
Key: MODEL_API_KEY (from ~/.config/meta/meta.env, sourced by the caller)."""
import json, os, sys, urllib.request
body = json.dumps({"model": os.environ.get("MUSE_MODEL", "muse-wonder-1.0"), "input": sys.stdin.read(),
                   "max_output_tokens": int(os.environ.get("MUSE_MAX_TOKENS", "4000")), "reasoning": {"effort": os.environ.get("MUSE_EFFORT", "medium")}}).encode()
req = urllib.request.Request("https://api.meta.ai/v1/responses", data=body,
                             headers={"Content-Type": "application/json", "Authorization": "Bearer " + os.environ["MODEL_API_KEY"]})
d = json.load(urllib.request.urlopen(req, timeout=600))
txt = "".join(c.get("text", "") for o in d.get("output", []) if o.get("type") == "message" for c in o.get("content", []))
if not txt.strip():
    sys.exit("empty reply: " + str(d.get("status")))
print(txt)
