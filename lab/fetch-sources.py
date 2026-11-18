#!/usr/bin/env python3
"""Fetch exact source revisions; never overwrite an existing checkout."""
import json
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parent
for name,spec in json.loads((ROOT/'sources.lock.json').read_text()).items():
    path=ROOT/'sources'/name
    if not path.exists():
        path.mkdir(parents=True)
        for args in [('init',),('remote','add','origin',spec['url']),
                     ('fetch','--depth=1','origin',spec['commit']),('checkout','--detach','FETCH_HEAD')]:
            subprocess.run(['git','-C',str(path),*args],check=True)
    sha=subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip()
    if sha!=spec['commit']: raise SystemExit(f'{name}: revision mismatch; existing checkout preserved')
    if subprocess.check_output(['git','-C',str(path),'status','--porcelain','--untracked-files=no'],text=True):
        raise SystemExit(f'{name}: tracked modifications present')
    print(f'{name}: {sha}')
