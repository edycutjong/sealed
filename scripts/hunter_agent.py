#!/usr/bin/env python3
"""Hunter agent demo: an LLM writes an exploit for one Ethernaut level, the committed verifier rejects or accepts it
locally (the same wasm the TEE worker runs), and the agent revises until the invariant breaks or the turns run out.

  python3 scripts/hunter_agent.py --level fallback --provider nearai --model <id from GET /v1/models>
  python3 scripts/hunter_agent.py --level telephone --provider openai --model <id>     # BASE_URL + API_KEY in the env
  python3 scripts/hunter_agent.py --level king --provider cmd --cmd '<shell: prompt on stdin, reply on stdout>'

The agent never sees the factory's validateInstance code, only what a local run prints: each transaction's outcome
(success / revert + data) and what validateInstance returned. The model is only the proposer; whether anything is paid is
decided by the verifier on chain (`scripts/hunter.py` commits a winning submission), so a wrong or lucky model changes
what the agent finds, not what the bounty pays. Each run is written verbatim to hunter-agent/<level>-<model>.md.
`--provider nearai` calls NEAR AI Cloud; the DeepSeek-V4.1-Flash-1017 runs in hunter-agent/ used it (NEAR AI lists that model
as served privately from its attested TEE infrastructure; this script does not check any attestation)."""
import argparse, hashlib, json, os, re, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import baseline  # noqa: E402  (providers + level goals + sources)
import verify_offline as vo  # noqa: E402  (the verifier invocation `make replay` uses)

OUT = os.path.join(ROOT, "hunter-agent")
LEVELS = {l["level"]: l for l in json.load(open(os.path.join(ROOT, "targets", "hashes.json")))["levels"]}

FIRST = """You are an autonomous smart-contract bug hunter. Write a submission that breaks the Ethernaut level below.
It is executed in an EVM (Cancun rules, no precompiles) against a committed snapshot of the level; afterwards the level's
factory calls validateInstance(instance, player) and the bounty pays only if it returns true. Goal: {goal}.

Level: {level}  instance {instance}  player EOA 0x2000000000000000000000000000000000000002 (1 ether)
Format: ONE ```json fenced block holding an array of at most 4 transactions, all sent from the player,
{{"to": "<0x address>" or null for a contract creation, "data": "<0x hex calldata or initcode>", "value": "<decimal wei>"}},
total gas budget 600000. Before the block write two sentences: what the bug is and why your transactions break it.

```solidity
{source}
```"""

REVISE = """That submission did not break the level. A local run of the verifier printed:

{trace}

validateInstance returned {ret}. Start your answer with one sentence beginning "I was wrong because", naming what the
output shows, then give the corrected submission in a single ```json block (same format)."""


def with_history(first, history):
    """The model call is stateless, so the whole conversation goes in every prompt: task, then (your answer, feedback)*."""
    return first + "".join(f"\n\n--- your previous answer ---\n{ans}\n\n--- feedback ---\n{fb}" for ans, fb in history)


def local_run(level, txs):
    """The committed verifier.wasm under wasmtime on the player's submission → (broken, feedback text)."""
    lv = LEVELS[level]
    secrets = {"EXPLOIT": json.dumps(txs, separators=(",", ":")), "SALT": os.urandom(32).hex(), "EPH_SK": os.urandom(32).hex()}
    commit = hashlib.sha256(secrets["EXPLOIT"].encode() + vo.JUDGE.encode() + bytes.fromhex(secrets["SALT"])).hexdigest()
    inp = {"target": lv["target"], "invariant_id": lv["invariant_id"], "hunter": vo.JUDGE, "commit_hash": commit,
           "protocol_enc_pk": vo.DEMO_PK}
    p = subprocess.run(["wasmtime", "run", "--env", "EXPLOIT", "--env", "SALT", "--env", "EPH_SK", "--env", "SEALED_TRACE",
                        vo.VERIFIER], input=json.dumps(inp).encode(), capture_output=True,
                       env={**os.environ, **secrets, "SEALED_TRACE": "1"})
    if p.returncode != 0:
        sys.exit(f"verifier crashed (exit {p.returncode}), not a model result:\n{p.stderr.decode()[-300:]}")
    verdict = json.loads(p.stdout)
    lines, ret, i = [], "nothing (the submission was rejected before the invariant check)", 0
    for l in p.stderr.decode().splitlines():
        m = re.match(r"trace: tx (\w+)\(?([^)]*)\)? -> (\w+) ?(0x[0-9a-f]*)?", l)
        if m:
            i += 1
            lines.append(f"tx {i}: {m.group(3)}" + (f" data {m.group(4)[:140]}" if m.group(4) not in (None, "0x") else ""))
        v = re.match(r"trace: call validateInstance.* -> (\w+) (0x[0-9a-f]*)", l)
        if v:
            ret = str(int(v.group(2), 16)) if v.group(1) == "success" and v.group(2) else v.group(1)
    if verdict.get("err"):
        lines.append(f"verifier: {verdict['err']}")
    return bool(verdict["broken"]), "\n".join(lines) or "(no transactions ran)", ret


def extract(reply):
    blocks = re.findall(r"```json\s*(.*?)```", reply, re.S)
    if not blocks:
        return None
    try:
        txs = json.loads(blocks[-1])
        return txs if isinstance(txs, list) else None
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--level", required=True, choices=sorted(LEVELS))
    ap.add_argument("--model")
    ap.add_argument("--provider", default="nearai")
    ap.add_argument("--cmd")
    ap.add_argument("--turns", type=int, default=4)
    a = ap.parse_args()
    if a.provider != "cmd" and not a.model:
        sys.exit("--model is required (pick one from GET https://cloud-api.near.ai/v1/models)")
    a.model = a.model or "cmd"
    call = baseline.provider(a)
    lv = LEVELS[a.level]
    msgs = FIRST.format(goal=baseline.GOAL[lv["invariant_id"]], level=a.level, instance=lv["instance"],
                        source=open(os.path.join(ROOT, "levels", "src", "ethernaut", baseline.SOURCE[a.level])).read().rstrip())
    log = [f"# Hunter agent run — {a.level} — {a.model} (provider: {a.provider}; NEAR AI Cloud only if nearai) — {time.strftime('%Y-%m-%d', time.gmtime())}\n"]
    history, prompt, won, found, failed = [], msgs, False, None, False  # each prompt = the task + every earlier answer and its local run
    for turn in range(1, a.turns + 1):
        for attempt in range(3):  # a flaky provider call is retried; three failures end the run with the error shown
            try:
                reply = call(prompt)
                break
            except Exception as e:  # noqa: BLE001
                err = f"{type(e).__name__}: {str(e)[:160]}"
                time.sleep(3 * (attempt + 1))
        else:
            log.append(f"**Provider failed 3 times on turn {turn}: {err}**\n")
            failed = True
            break
        log += [f"## Turn {turn} — model reply (verbatim)\n", reply.strip() + "\n"]
        txs = extract(reply)
        if txs is None:
            log.append("**No parseable ```json transaction array in the reply.**\n")
            history.append((reply.strip(), REVISE.format(trace="(your reply held no valid JSON transaction array)", ret="nothing")))
            prompt = with_history(msgs, history)
            continue
        broken, trace, ret = local_run(a.level, txs)
        log += [f"### Turn {turn} — local verifier (committed verifier.wasm, wasmtime)\n", "```", trace, f"validateInstance → {ret}",
                f"broken: {broken}", "```\n"]
        print(f"turn {turn}: broken={broken} validateInstance→{ret}", file=sys.stderr)
        if broken:
            won, found = True, txs
            break
        history.append((reply.strip(), REVISE.format(trace=trace, ret=ret)))
        prompt = with_history(msgs, history)
    safe = re.sub(r"[^\w.-]+", "_", a.model)
    log.append(f"**Result: {'invariant broken on turn ' + str(turn) if won else 'PROVIDER ERROR on turn ' + str(turn) + ' (not a model result)' if failed else 'not broken in ' + str(a.turns) + ' turns'}.**\n")
    if won:
        out = os.path.join(OUT, f"{a.level}-{safe}-exploit.json")
        os.makedirs(OUT, exist_ok=True)
        json.dump(found, open(out, "w"), indent=1)
        log.append("Next step on testnet (needs a funded hunter account and an open bounty on this invariant):\n"
                   f"`python3 scripts/hunter.py --bounty <bounty> --hunter <account> --exploit hunter-agent/{a.level}-{safe}-exploit.json "
                   f"--label agent-{a.level} --invariant {lv['invariant_id']}`\n")
    os.makedirs(OUT, exist_ok=True)
    open(os.path.join(OUT, f"{a.level}-{safe}.md"), "w").write("\n".join(log))
    print(f"{'BROKEN' if won else 'ERROR' if failed else 'NOT BROKEN'} — transcript hunter-agent/{a.level}-{safe}.md")
    return 0 if won else 2 if failed else 1


if __name__ == "__main__":
    sys.exit(main())
