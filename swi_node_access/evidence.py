"""
SWI Node-Access Boundary — Evidence persistence (Stage 1 demonstrator)

Section 25 requires an evidence record for every access decision. The V1
hardening review found that Module 07 claims tamper-evidence but is
actually non-persistent in-memory-only. This module deliberately follows
Module 09's REAL pattern instead: append-only, hash-chained, on disk,
verified by re-reading the file — not by trusting an in-memory list.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Optional

GENESIS_HASH = "0" * 64


def _line_hash(prev_hash: str, record: dict) -> str:
    body = json.dumps({"prev_hash": prev_hash, "record": record}, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass
class VerifyResult:
    valid: bool
    broken_at_line: Optional[int] = None
    lines_checked: int = 0


class EvidenceLog:
    """Append-only, hash-chained, ON-DISK evidence log for access decisions."""

    def __init__(self, log_path: str):
        self.log_path = log_path
        if not os.path.exists(log_path):
            open(log_path, "w").close()

    def _last_hash(self) -> str:
        last = GENESIS_HASH
        with open(self.log_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = json.loads(line)["hash"]
        return last

    def append(self, record: dict) -> str:
        prev_hash = self._last_hash()
        h = _line_hash(prev_hash, record)
        line = {"prev_hash": prev_hash, "record": record, "hash": h}
        with open(self.log_path, "a") as f:
            f.write(json.dumps(line, default=str) + "\n")
        return h

    def verify(self) -> VerifyResult:
        prev_hash = GENESIS_HASH
        count = 0
        with open(self.log_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                count += 1
                entry = json.loads(line)
                expected = _line_hash(entry["prev_hash"], entry["record"])
                if entry["prev_hash"] != prev_hash or entry["hash"] != expected:
                    return VerifyResult(valid=False, broken_at_line=count, lines_checked=count)
                prev_hash = entry["hash"]
        return VerifyResult(valid=True, lines_checked=count)

    def read_all(self) -> list:
        records = []
        with open(self.log_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line)["record"])
        return records
