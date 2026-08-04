from __future__ import annotations
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
from activity_attribution import extract_dns_query
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.pcapd import PcapdService

async def watch() -> None:
    lockdown = await create_using_usbmux(autopair=False, connection_type='USB')
    try:
        service = PcapdService(lockdown=lockdown)
        await service.connect()
        print(json.dumps({'type': 'status', 'state': 'listening', 'detail': 'Evidence-based privacy classification.'}, ensure_ascii=False), flush=True)
        async for packet in service.watch():
            question = extract_dns_query(bytes(packet.data))
            if not question:
                continue
            observed_at = datetime.fromtimestamp(packet.seconds + packet.microseconds / 1000000).astimezone().isoformat(timespec='seconds')
            payload = {'type': 'appDomain', 'observedAt': observed_at, 'processName': str(packet.comm or ''), 'pid': int(packet.pid or 0), 'interface': str(packet.interface_name or ''), 'source': 'ios-pcap', 'confidence': 'exact-process', **question}
            print(json.dumps(payload, ensure_ascii=False), flush=True)
    finally:
        await lockdown.close()

def main() -> None:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    asyncio.run(watch())
if __name__ == '__main__':
    main()
