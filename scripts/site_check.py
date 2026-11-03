#!/usr/bin/env python3
"""E2E check of the judge-facing static site in docs/ (landing, /pitch/, /judge/).

Offline (default): every page exists, carries its title, the /judge page states the claim and both receipts, and every
local src/href resolves to a file in docs/. `--live URL` also fetches the deployed pages with no cookies or credentials
and asserts 200 + the same claim, so a /judge page that breaks on submission day fails CI.
"""
import argparse, re, sys, urllib.request
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs"
PAGES = {"": "index.html", "pitch/": "pitch/index.html", "judge/": "judge/index.html"}
CLAIM = "Bug bounties that pay for an executed break of a committed invariant on a committed snapshot"
JUDGE_MUST = [CLAIM, "5 of 5", "0 of 21", "make replay", "make verify"]


def local_refs(page: Path, html: str):
    for ref in re.findall(r'(?:src|href)="([^"#?]+)', html):
        if re.match(r"^(https?:|mailto:|data:|//)", ref):
            continue
        base = DOCS if ref.startswith("/") else page.parent
        target = (base / ref.lstrip("/")).resolve()
        if target.is_dir() or ref.endswith("/"):
            target = target / "index.html"
        yield ref, target


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", metavar="URL", help="also fetch the deployed site, e.g. https://sealed.edycu.dev")
    a = ap.parse_args()
    fails = []
    for route, rel in PAGES.items():
        page = DOCS / rel
        if not page.is_file():
            fails.append(f"missing docs/{rel}")
            continue
        html = page.read_text(encoding="utf-8")
        if not re.search(r"<title>[^<]{3,}</title>", html):
            fails.append(f"docs/{rel}: no <title>")
        for ref, target in local_refs(page, html):
            if not target.exists():
                fails.append(f"docs/{rel}: broken local ref {ref}")
        print(f"OK   docs/{rel}")
    judge = (DOCS / PAGES["judge/"]).read_text(encoding="utf-8")
    fails += [f"/judge: missing '{s}'" for s in JUDGE_MUST if s not in judge]
    if a.live:
        for route in PAGES:
            url = a.live.rstrip("/") + "/" + route
            req = urllib.request.Request(url, headers={"User-Agent": "sealed-ci-site-check"})
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    body, code = r.read().decode("utf-8", "replace"), r.status
            except Exception as e:  # noqa: BLE001 - report any network failure as a check failure
                fails.append(f"{url}: {e}")
                continue
            if code != 200 or (route == "judge/" and CLAIM not in body):
                fails.append(f"{url}: status {code} or claim missing")
            else:
                print(f"LIVE {code} {url}")
    for f in fails:
        print(f"FAIL {f}")
    print(f"site: {len(PAGES)} pages · {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
