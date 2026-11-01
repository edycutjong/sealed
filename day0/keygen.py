#!/usr/bin/env python3
"""Generate an ed25519 NEAR key for <account_id> into ~/.config/near/sealed-testnet/<account_id>.json (mode 600).

Prints only the PUBLIC key. Never overwrites an existing file."""
import json, os, sys
import base58
from nacl.signing import SigningKey

DIR = os.path.expanduser("~/.config/near/sealed-testnet")

def main(account_id: str) -> None:
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    path = os.path.join(DIR, f"{account_id}.json")
    if os.path.exists(path):
        print(json.load(open(path))["public_key"])
        return
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    cred = {
        "account_id": account_id,
        "public_key": "ed25519:" + base58.b58encode(pk).decode(),
        "private_key": "ed25519:" + base58.b58encode(bytes(sk) + pk).decode(),
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cred, f)
    print(cred["public_key"])

if __name__ == "__main__":
    main(sys.argv[1])
