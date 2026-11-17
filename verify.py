#!/usr/bin/env python3
"""Check the Sky AI Bets archive yourself, without trusting the page.

    python3 verify.py                 # chain of hashes (no extra packages needed)
    pip install pynacl && python3 verify.py   # also checks every signature against pubkey.txt

The chain check recomputes each record's SHA-256 from its contents (canonical JSON: sorted keys, no spaces,
UTF-8, without the "hash" and "sig" fields) and makes sure every record names the previous one's hash.
Changing, removing or inserting any old record breaks every hash after it.
Bitcoin time stamps: install the OpenTimestamps client (pip install opentimestamps-client) and run
    ots verify stamps/000123.txt.ots
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent


def canonical(r: dict) -> str:
    return json.dumps({k: v for k, v in r.items() if k not in ("hash", "sig")},
                      sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def main() -> int:
    records = [json.loads(l) for l in (HERE / "ledger.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    try:
        from nacl.signing import VerifyKey
        key = VerifyKey(base64.b64decode((HERE / "pubkey.txt").read_text().strip()))
    except ImportError:
        key = None
    prev = "GENESIS"
    for i, r in enumerate(records, 1):
        h = hashlib.sha256(canonical(r).encode("utf-8")).hexdigest()
        if r["seq"] != i or r["prev_hash"] != prev or h != r["hash"]:
            print(f"❌ запись {i}: цепочка нарушена")
            return 1
        if key is not None:
            try:
                key.verify(r["hash"].encode(), base64.b64decode(r["sig"]))
            except Exception:
                print(f"❌ запись {i}: подпись не сходится")
                return 1
        prev = r["hash"]
    print(f"✅ {len(records)} записей: цепочка цела" + (", подписи верны" if key else
          " (подписи не проверены: pip install pynacl)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
