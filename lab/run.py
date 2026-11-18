#!/usr/bin/env python3
"""Explicit opt-in virtual LTE test with fresh state and guaranteed teardown."""
import argparse
import datetime
import ipaddress
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parent
COMPOSE=['docker','compose','-f',str(ROOT/'compose.yaml')]
def run(*args,**kwargs): return subprocess.run(args,check=True,cwd=ROOT,**kwargs)
def compose(*args,**kwargs): return run(*COMPOSE,*args,**kwargs)
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--ciphering',choices=['NEA0','NEA2'],default='NEA0')
p.add_argument('--ue-subnet',default='10.45.0.0/24')
p.add_argument('--build',action='store_true',help='build core, RAN and gateway before running')
a=p.parse_args()
# Refuse to stop a lab belonging to another invocation.
existing=subprocess.check_output(['docker','ps','-aq','--filter','label=com.docker.compose.project=s1n2-virtual-lab'],text=True).strip()
if existing: raise SystemExit('Existing lab containers found; stop that run before starting another')
labnet=ipaddress.ip_network('10.203.0.0/24')
for route in json.loads(subprocess.check_output(['ip','-j','-4','route'],text=True)):
    if route.get('dst','default')!='default' and labnet.overlaps(ipaddress.ip_network(route['dst'],strict=False)):
        raise SystemExit('Lab network overlaps a host route')
run(sys.executable,str(ROOT/'fetch-sources.py'))
if a.build:
    run('docker','build','-f','Dockerfile.core','-t','s1n2-virtual-core:2.7.2','.')
    run('docker','build','-f','Dockerfile.ran','-t','s1n2-virtual-ran:23.11','.')
    run('docker','build','-t','s1n2-gateway:dev','..')
# Move previous credentials and logs together, outside the current log directory.
runtime=ROOT/'runtime'
if runtime.exists():
    archive=ROOT/'runtime-history'/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    archive.parent.mkdir(exist_ok=True,mode=0o700)
    shutil.move(str(runtime),str(archive))
run(sys.executable,str(ROOT/'prepare.py'),'--ciphering',a.ciphering,'--ue-subnet',a.ue_subnet)
compose('config','--quiet')
try:
    compose('up','-d','mongo','core')
    for _ in range(45):
        amf=runtime/'logs/amf.log';smf=runtime/'logs/smf.log'
        if amf.exists() and smf.exists() and 'ngap_server()' in amf.read_text() and 'PFCP associated' in smf.read_text(): break
        time.sleep(1)
    else: raise RuntimeError('Core startup timed out; see private runtime/logs')
    compose('up','-d','gateway','enb','ue')
    run(sys.executable,str(ROOT/'check-lab.py'))
finally:
    # Attempt down even if a process already exited or stop failed.
    try: compose('stop','-t','3','ue','enb')
    finally: compose('down','-v')
