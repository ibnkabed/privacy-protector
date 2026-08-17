import argparse
import asyncio
import plistlib
import sys
from pathlib import Path
from pymobiledevice3.cli.syslog import SyslogFormat, syslog_live
from pymobiledevice3.lockdown import create_using_tcp

async def capture(args: argparse.Namespace) -> None:
    pair_record_path = Path(args.pair_record)
    with pair_record_path.open('rb') as pair_record_file:
        pair_record = plistlib.load(pair_record_file)
    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lockdown = await create_using_tcp(args.host, autopair=False, pair_record=pair_record, keep_alive=True)
    try:
        with output_path.open('a', encoding='utf-8', buffering=1) as output_file:
            await syslog_live(service_provider=lockdown, out=output_file, pid=-1, process_name=None if args.all_processes else args.process_name, match=[], invert_match=[], match_insensitive=[], invert_match_insensitive=[], include_label=False, regex=[], insensitive_regex=[], output_format=SyslogFormat.TEXT)
    finally:
        await lockdown.close()

def main() -> None:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='backslashreplace')
    parser = argparse.ArgumentParser(description='Capture one iOS process syslog over an existing Wi-Fi pairing.')
    parser.add_argument('--host', required=True)
    parser.add_argument('--pair-record', required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--process-name')
    selection.add_argument('--all-processes', action='store_true')
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    asyncio.run(capture(args))
if __name__ == '__main__':
    main()
