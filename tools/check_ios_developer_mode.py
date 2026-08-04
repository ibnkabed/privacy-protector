from __future__ import annotations
import argparse
import asyncio
import json
import plistlib
from datetime import datetime, timezone
from pathlib import Path
from pymobiledevice3.lockdown import create_using_tcp

async def check_status(host: str, pair_record_path: Path) -> dict[str, object]:
    with pair_record_path.open('rb') as handle:
        pair_record = plistlib.load(handle)
    lockdown = await create_using_tcp(host, autopair=False, pair_record=pair_record, keep_alive=False)
    try:
        enabled = bool(await lockdown.get_developer_mode_status())
        return {'ok': True, 'enabled': enabled, 'productVersion': str(lockdown.product_version or ''), 'checkedAt': datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')}
    finally:
        await lockdown.close()

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--pair-record', required=True, type=Path)
    args = parser.parse_args()
    try:
        payload = asyncio.run(check_status(args.host, args.pair_record))
    except Exception as exc:
        payload = {'ok': False, 'code': 'device_unavailable', 'error': str(exc).strip()[:400] or 'The requested operation could not be completed.'}
    print(json.dumps(payload, ensure_ascii=False))
if __name__ == '__main__':
    main()
