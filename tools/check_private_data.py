"""Release scanner: stop personal data from reaching the public repository.

Checks every tracked or new (not ignored) file and the message of every commit not yet on
origin/main against the patterns in `.private-patterns` (a local file kept out
of Git, one regular expression per line). Without that file only the generic
checks run: secret-looking keys and absolute user-profile paths.

Also prints a count of Arabic text lines left inside Python files, so they can
move to the translation files. That count is a report, not a failure.

Exit code 1 when anything personal is found.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS_FILE = ROOT / ".private-patterns"
GENERIC = [
    r"[A-Za-z]:\\Users\\(?!<|%|\{|Public\b|Example\b|Default\b)[A-Za-z0-9._-]+\\",
    r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}",
    r"\bAIza[0-9A-Za-z_-]{30,}",
    r"\bghp_[A-Za-z0-9]{30,}",
]
ARABIC = re.compile(r"[؀-ۿ]")
SKIP_SUFFIXES = {".png", ".ico", ".jpg", ".jpeg", ".gif", ".webp", ".exe", ".dll", ".zip"}


def load_patterns() -> list[re.Pattern[str]]:
    lines = GENERIC[:]
    if PATTERNS_FILE.exists():
        for raw in PATTERNS_FILE.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if raw and not raw.startswith("#"):
                lines.append(raw)
    return [re.compile(line, re.IGNORECASE) for line in lines]


def git(*args: str) -> str:
    result = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, encoding="utf-8")
    return result.stdout if result.returncode == 0 else ""


def scan() -> tuple[list[str], dict[str, int]]:
    patterns = load_patterns()
    findings: list[str] = []
    arabic: dict[str, int] = {}
    names = git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split("\0")
    for name in sorted(set(names)):
        path = ROOT / name
        if not name or path.suffix.lower() in SKIP_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for pattern in patterns:
                if pattern.search(line):
                    findings.append(f"{name}:{number}: matches {pattern.pattern!r}")
            if name.endswith(".py") and ARABIC.search(line):
                arabic[name] = arabic.get(name, 0) + 1
    if git("rev-parse", "--verify", "-q", "origin/main"):
        for entry in git("log", "--format=%H%x1f%B%x1e", "origin/main..HEAD").split("\x1e"):
            if "\x1f" not in entry:
                continue
            sha, message = entry.strip().split("\x1f", 1)
            for pattern in patterns:
                if pattern.search(message):
                    findings.append(f"commit {sha[:8]} message: matches {pattern.pattern!r}")
    return findings, arabic


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    findings, arabic = scan()
    for line in findings:
        print(line)
    if arabic:
        print("Arabic text lines in Python files: " + ", ".join(f"{k}={v}" for k, v in sorted(arabic.items())))
    print("private-data scan: " + ("FAILED" if findings else "clean"))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
