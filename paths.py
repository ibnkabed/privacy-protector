r"""Where Privacy Protector reads its bundled files and keeps its data.

- APP_ROOT: the program's own files (web dashboard, scripts, defaults). Inside the
  installed exe this is the unpacked bundle.
- DATA_ROOT: everything the app writes. `PRIVACY_PROTECTOR_DATA_DIR` wins; the
  installed exe uses %LOCALAPPDATA%\PrivacyProtector; a source checkout uses ./data.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

FROZEN = bool(getattr(sys, "frozen", False))
APP_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def _data_root() -> Path:
    override = os.environ.get("PRIVACY_PROTECTOR_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    if FROZEN:
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "PrivacyProtector"
    return APP_ROOT / "data"


DATA_ROOT = _data_root()
PC_ROOT = DATA_ROOT / "pc"
RUNTIME_ROOT = DATA_ROOT / "runtime"
