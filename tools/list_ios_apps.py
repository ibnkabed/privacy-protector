from __future__ import annotations

import argparse
import asyncio
import json
import plistlib
import sys
from pathlib import Path

from pymobiledevice3.lockdown import create_using_tcp, create_using_usbmux
from pymobiledevice3.services.installation_proxy import InstallationProxyService


async def list_apps(args: argparse.Namespace) -> list[dict[str, str]]:
    if args.usb:
        # Via USB: reads through Apple Mobile Device service, pairs if needed after
        # "Trust This Computer".
        lockdown = await create_using_usbmux(autopair=True)
        try:
            # Keeps network reading available after unplugging; iPhone disconnects every
            # six hours without cable.
            await lockdown.set_value(True, domain="com.apple.mobile.wireless_lockdown", key="EnableWifiConnections")
        except Exception:  # noqa: BLE001 - USB reading suffices this time
            pass
    else:
        with Path(args.pair_record).open("rb") as handle:
            pair_record = plistlib.load(handle)
        lockdown = await create_using_tcp(
            args.host,
            autopair=False,
            pair_record=pair_record,
            keep_alive=False,
        )
    try:
        raw = await InstallationProxyService(lockdown=lockdown).get_apps(
            application_type="User"
        )
        return [
            {
                "bundleID": str(metadata.get("CFBundleIdentifier") or bundle_id),
                "name": str(
                    metadata.get("CFBundleDisplayName")
                    or metadata.get("CFBundleName")
                    or bundle_id
                ),
                "processName": str(metadata.get("CFBundleExecutable") or ""),
                "source": "device",
            }
            for bundle_id, metadata in raw.items()
        ]
    finally:
        await lockdown.close()


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--usb", action="store_true")
    parser.add_argument("--host")
    parser.add_argument("--pair-record")
    print(json.dumps(asyncio.run(list_apps(parser.parse_args())), ensure_ascii=False))


if __name__ == "__main__":
    main()
