"""Reference implementation of the Pelco release format: build, sign, pack and check releases."""
from pathlib import Path

__version__ = (Path(__file__).resolve().parent.parent / "version.txt").read_text(encoding="utf-8").strip()
