"""Result codes, read from spec/result-codes.json so the numbers can't drift from the spec."""
import json
from pathlib import Path

SPEC = Path(__file__).resolve().parent.parent / "spec"

with open(SPEC / "result-codes.json", encoding="utf-8") as _f:
    NUMBERS = {c["code"]: c["number"] for c in json.load(_f)["codes"]}


class Rejected(Exception):
    """A check failed with one of the spec's result codes."""

    def __init__(self, code, detail=""):
        if code not in NUMBERS:
            raise ValueError(f"unknown result code {code}")
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
