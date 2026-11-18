#!/usr/bin/env python3
"""Check the currently running synthetic lab; never read deployment credentials."""
import datetime
import json
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parent
PROFILE = json.loads((ROOT / 'runtime/profile.json').read_text())
UE_IP = PROFILE['ue_ip']
GATEWAY = PROFILE['gateway']
COMPOSE = ['docker', 'compose', '-f', str(ROOT / 'compose.yaml')]

def run(*args, timeout=20):
    return subprocess.run([*COMPOSE, *args], cwd=ROOT, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)

def log(name):
    p = ROOT / 'runtime/logs' / name
    return p.read_text(errors='replace') if p.exists() else ''

for _ in range(30):
    result = run('exec', '-T', 'ue', 'ip', '-j', '-4', 'addr', 'show', 'dev', 'tun_srsue')
    if result.returncode == 0:
        break
    time.sleep(1)

addresses = []
if result.returncode == 0:
    addresses = [a['local'] for item in json.loads(result.stdout) for a in item.get('addr_info', [])]

gateway, amf, smf, upf = [log(name) for name in ['gateway.log', 'amf.log', 'smf.log', 'upf.log']]
checks = {
    's1_setup_response_sent': 'NGSetupResponse -> S1SetupResponse sent' in gateway,
    'security_mode_complete_converted': '5G Security Mode Complete created' in gateway,
    'amf_registration_complete': 'Registration complete' in amf,
    'ue_attached': 'Network attach successful.' in log('ue-console.log'),
    'ue_expected_ip': UE_IP in addresses,
    'smf_expected_ip': f'IPv4[{UE_IP}]' in smf,
    'upf_expected_ip': f'IPv4[{UE_IP}]' in upf,
}
results = {}
for direction, service, interface, destination in [
        ('ue_to_upf', 'ue', 'tun_srsue', GATEWAY),
        ('upf_to_ue', 'core', 'ogstun', UE_IP)]:
    result = run('exec', '-T', service, 'ping', '-n', '-I', interface, '-c', '5', '-W', '2', destination)
    match = re.search(r'(\d+) packets transmitted, (\d+) received,.*?([\d.]+)% packet loss', result.stdout)
    summary = {'exit_code': result.returncode}
    if match:
        summary.update(transmitted=int(match[1]), received=int(match[2]), loss_percent=float(match[3]))
    results[direction] = summary
    checks[direction] = result.returncode == 0 and bool(match) and match[2] == '5'
    (ROOT / f'runtime/{direction}-ping.txt').write_text(result.stdout)

report = {'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'profile': json.loads((ROOT/'runtime/profile.json').read_text()),
          'checks': checks, 'ping': results, 'passed': all(checks.values())}
(ROOT / 'runtime/result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
raise SystemExit(0 if report['passed'] else 1)
