from __future__ import annotations
import argparse
import asyncio
import json
import plistlib
import sys
from pathlib import Path
from pymobiledevice3.lockdown import create_using_tcp
from pymobiledevice3.services.installation_proxy import InstallationProxyService

async def list_apps(args: argparse.Namespace) -> list[dict[str, str]]:
    with Path(args.pair_record).open('rb') as handle:
        pair_record = plistlib.load(handle)
    lockdown = await create_using_tcp(args.host, autopair=False, pair_record=pair_record, keep_alive=False)
    try:
        raw = await InstallationProxyService(lockdown=lockdown).get_apps(application_type='User')
        return [{'bundleID': str(metadata.get('CFBundleIdentifier') or bundle_id), 'name': str(metadata.get('CFBundleDisplayName') or metadata.get('CFBundleName') or bundle_id), 'processName': str(metadata.get('CFBundleExecutable') or ''), 'source': 'device'} for bundle_id, metadata in raw.items()]
    finally:
        await lockdown.close()

def main() -> None:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--pair-record', required=True)
    print(json.dumps(asyncio.run(list_apps(parser.parse_args())), ensure_ascii=False))
if __name__ == '__main__':
    main()
