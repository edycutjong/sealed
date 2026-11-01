#!/usr/bin/env python3
"""Fail on anything unfinished in the judge-facing files: placeholder markers, dead relative links,
kitchen files that must never ship, and a pinned verifier hash that no longer matches the committed wasm.

    python3 scripts/check_submission_readiness.py [extra-file ...]

Extra files (e.g. a drafted submission text kept outside the repo) are scanned for placeholders too.
Exit 0 = ready, 1 = findings printed as `path:line: reason`.
"""
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROSE = ["README.md", "DEMO.md", "ARCHITECTURE.md", "docs/DX-REPORT.md", "SECURITY.md", "CONTRIBUTING.md"]
PLACEHOLDER = re.compile(
    r"0x…|0x\.\.\.|\bTBD\b|\bTODO\b|\bFIXME\b|\bXXX\b|lorem ipsum|<your[- ][a-z -]+>|\[(?:link|url|todo)\]|"
    r"https?://(?:example\.com|localhost|127\.0\.0\.1)|\bplaceholder\b",
    re.I,
)
KITCHEN = re.compile(r"(^|/)(specs|audits?|predictions?|radar)(/|$)|progress\.md$|HUMAN-TODO|(^|/)(CLAUDE|AGENTS)\.md$|(^|/)\.claude/|\.env$|\.pem$|\.key$")
LINK = re.compile(r"\]\((?!https?:|#|mailto:)([^)\s#]+)")


def rel(path):
    return path.relative_to(ROOT) if path.is_relative_to(ROOT) else path


def scan(path, problems):
    in_fence = False
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
        m = PLACEHOLDER.search(line)
        if m and not (in_fence and m.group(0).lower().startswith("https?://")):
            problems.append(f"{rel(path)}:{n}: placeholder `{m.group(0)}`")
        if path.suffix == ".md" and not in_fence:
            for link in LINK.findall(line):
                if not (path.parent / link).exists():
                    problems.append(f"{rel(path)}:{n}: dead relative link `{link}`")


def main():
    problems = []
    for rel in PROSE:
        p = ROOT / rel
        if p.exists():
            scan(p, problems)
        elif rel in ("README.md", "DEMO.md", "ARCHITECTURE.md"):
            problems.append(f"{rel}: missing")
    for extra in sys.argv[1:]:
        scan(Path(extra).resolve(), problems)

    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True).stdout.split()
    for f in tracked:
        if KITCHEN.search(f):
            problems.append(f"{f}: kitchen/secret-shaped file is tracked")

    sha = (ROOT / "verifier.wasm.sha256").read_text().split()[0]
    actual = hashlib.sha256((ROOT / "verifier.wasm").read_bytes()).hexdigest()
    if sha != actual:
        problems.append(f"verifier.wasm.sha256 {sha[:12]}… != committed verifier.wasm {actual[:12]}…")

    for p in problems:
        print(p)
    print(f"readiness: {'FAIL' if problems else 'OK'} ({len(problems)} finding(s))")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
