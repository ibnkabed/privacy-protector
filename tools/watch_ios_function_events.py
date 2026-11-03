from __future__ import annotations

import argparse
import asyncio
import json
import os
import plistlib
import re
import sys
from pathlib import Path


SITE_PACKAGES = Path(__file__).resolve().parents[1] / ".venv" / "Lib" / "site-packages"
PYWIN32_DLL_HANDLE = None
if hasattr(os, "add_dll_directory"):
    pywin32_dlls = SITE_PACKAGES / "pywin32_system32"
    if pywin32_dlls.exists():
        PYWIN32_DLL_HANDLE = os.add_dll_directory(str(pywin32_dlls))

from pymobiledevice3.cli.syslog import SyslogFormat, syslog_live
from pymobiledevice3.lockdown import create_using_tcp


LINE_PATTERN = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<process>[^\{\[]+).*?\[(?P<pid>\d+)\]"
)


class FunctionEventSink:
    def write(self, value: str) -> int:
        for line in str(value).splitlines():
            if "developermodestatus" not in line.lower():
                continue
            match = LINE_PATTERN.search(line)
            payload = {
                "type": "function",
                "observedAt": match.group("time") if match else "",
                "processName": match.group("process").strip() if match else "",
                "pid": int(match.group("pid")) if match else 0,
                "functionName": "MGGetBoolAnswer" if "MGGetBoolAnswer" in line else "local-status-query",
                "functionKey": "DeveloperModeStatus",
                "source": "ios-syslog",
                "confidence": "exact-marker",
            }
            print(json.dumps(payload, ensure_ascii=False), flush=True)
        return len(value)

    def flush(self) -> None:
        return None


async def watch(args: argparse.Namespace) -> None:
    with Path(args.pair_record).open("rb") as handle:
        pair_record = plistlib.load(handle)
    lockdown = await create_using_tcp(
        args.host,
        autopair=False,
        pair_record=pair_record,
        keep_alive=True,
    )
    try:
        print(
            json.dumps(
                {
                    "type": "status",
                    "state": "listening",
                    "detail": "Automatic monitoring of local function indicators is active",
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        await syslog_live(
            service_provider=lockdown,
            out=FunctionEventSink(),
            pid=-1,
            process_name=None,
            match=[],
            invert_match=[],
            match_insensitive=[],
            invert_match_insensitive=[],
            include_label=False,
            regex=[],
            insensitive_regex=[r"MGGetBoolAnswer|DeveloperModeStatus"],
            output_format=SyslogFormat.TEXT,
        )
    finally:
        await lockdown.close()
def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--pair-record", required=True)
    asyncio.run(watch(parser.parse_args()))


if __name__ == "__main__":
    main()
