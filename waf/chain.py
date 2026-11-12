"""Tamper-evident audit log: every entry stores the SHA-256 of the previous entry (a hash chain).

Editing or deleting any entry breaks every hash after it, and `verify` reports the first bad index.
Limits (single-file chain, not a distributed ledger): someone with write access can rebuild the whole chain,
and cutting entries off the END is undetectable unless the head hash is recorded elsewhere. `verify` prints
the head hash so it can be pinned externally (email, ticket, another host).

    python chain.py verify waf_chain.jsonl
"""
import hashlib
import json
import os
import sys
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64


def _hash(entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify(path):
    """Return (ok, count_or_bad_index, head_hash)."""
    prev, n = GENESIS, 0
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    return False, n, prev
                if e.get("index") != n or e.get("prev_hash") != prev or e.get("hash") != _hash(e):
                    return False, n, prev
                prev, n = e["hash"], n + 1
    return True, n, prev


class Chain:
    def __init__(self, path="waf_chain.jsonl"):
        ok, self.index, self.prev = verify(path)
        if not ok:
            raise ValueError(f"{path}: chain broken at entry {self.index}; refusing to append")
        self.path, self.lock = path, threading.Lock()

    def append(self, ip, request, score, decision):
        with self.lock:
            e = dict(index=self.index, ts=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                     ip=ip, request=request, score=round(float(score), 4), decision=decision, prev_hash=self.prev)
            e["hash"] = _hash(e)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(e) + "\n")
            self.index, self.prev = self.index + 1, e["hash"]
            return e


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "verify":
        sys.exit(__doc__)
    ok, n, head = verify(sys.argv[2])
    print(f"OK: {n} entries, head hash {head}" if ok else f"TAMPERED: chain breaks at entry {n}")
    sys.exit(0 if ok else 1)
