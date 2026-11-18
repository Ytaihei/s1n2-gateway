#!/usr/bin/env python3
"""Read only lab logs, redacting synthetic credentials and protocol key material."""
import argparse
import json
from pathlib import Path
import re
parser=argparse.ArgumentParser()
parser.add_argument('names', nargs='+')
parser.add_argument('--match', default='.')
parser.add_argument('--tail', type=int, default=35)
args=parser.parse_args()
root=Path(__file__).resolve().parent
credentials=json.loads((root/'runtime/credentials.json').read_text())
for name in args.names:
    path=root/'runtime/logs'/name
    if path.parent != root/'runtime/logs' or not path.is_file():
        print(f'{name}: unavailable')
        continue
    lines=path.read_text(errors='replace').splitlines()
    filtered=[]
    for line in lines:
        if not re.search(args.match, line, re.I):
            continue
        line=re.sub(r'\x1b\[[0-9;]*m','',line)
        for value in credentials.values():
            line=re.sub(re.escape(value),'[synthetic-redacted]',line,flags=re.I)
        line=re.sub(r'\b[0-9a-fA-F]{16,}\b','[hex-redacted]',line)
        line=re.sub(r'(?:\b[0-9a-fA-F]{2} ){8,}[0-9a-fA-F ]*','[bytes-redacted]',line)
        filtered.append(line)
    print(f'--- {name} ({len(filtered)} matching lines) ---')
    print('\n'.join(filtered[-args.tail:]))
