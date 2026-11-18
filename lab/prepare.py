#!/usr/bin/env python3
"""Generate isolated lab configuration and disposable synthetic credentials."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import yaml

parser = argparse.ArgumentParser()
parser.add_argument('--ciphering', choices=['NEA0', 'NEA2'], default='NEA0')
parser.add_argument('--ue-subnet', default='10.45.0.0/24')
args = parser.parse_args()
subnet = ipaddress.IPv4Network(args.ue_subnet)
if subnet.num_addresses < 8: parser.error('UE subnet must have at least eight addresses')
gateway = str(subnet.network_address + 1)
ue_ip = str(subnet.network_address + 2)
os.umask(0o077)
root = Path(__file__).resolve().parent
runtime = root / 'runtime'
config = runtime / 'config'
for path in [config / 'core', config / 'ran', runtime / 'logs']:
    path.mkdir(parents=True, exist_ok=True)
credentials_file = runtime / 'credentials.json'
if credentials_file.exists():
    credentials = json.loads(credentials_file.read_text())
else:
    credentials = {'imsi': '00101' + ''.join(str(secrets.randbelow(10)) for _ in range(10)),
                   'ki': secrets.token_hex(16), 'opc': secrets.token_hex(16)}
    credentials_file.write_text(json.dumps(credentials))
if 'imei' not in credentials:
    credentials['imei'] = '00000000' + ''.join(str(secrets.randbelow(10)) for _ in range(7))
    credentials_file.write_text(json.dumps(credentials))

for nf in ['nrf', 'scp', 'amf', 'smf', 'upf', 'ausf', 'udm', 'udr', 'pcf', 'bsf', 'nssf']:
    text = (root / f'sources/open5gs/configs/open5gs/{nf}.yaml.in').read_text()
    text = text.replace('@localstatedir@', '/opt/open5gs/var').replace('@sysconfdir@', '/opt/open5gs/etc')
    data = yaml.safe_load(text)
    data['logger'] = {'file': {'path': f'/runtime/logs/{nf}.log'}, 'level': 'info'}
    data['global']['max']['ue'] = 32
    if 'db_uri' in data:
        data['db_uri'] = 'mongodb://mongo/open5gs'
    if nf == 'nrf':
        data[nf]['serving'][0]['plmn_id'] = {'mcc': '001', 'mnc': '01'}
    if nf == 'amf':
        data[nf]['ngap']['server'][0]['address'] = '10.203.0.10'
        data[nf]['security']['ciphering_order'] = [args.ciphering]
        data[nf]['security']['integrity_order'] = ['NIA2']
        for field in ['guami', 'tai', 'plmn_support']:
            data[nf][field][0]['plmn_id'] = {'mcc': '001', 'mnc': '01'}
    if nf == 'upf':
        data[nf]['gtpu']['server'][0]['address'] = '10.203.0.10'
    if nf in ['smf', 'upf']:
        data[nf]['session'] = [{'subnet': str(subnet), 'gateway': gateway, 'dnn': 'internet'}]
    (config / 'core' / f'{nf}.yaml').write_text(yaml.safe_dump(data, sort_keys=False))

(config / 'auth_keys.yaml').write_text(yaml.safe_dump({
    'subscribers': [{key: credentials[key] for key in ['imsi', 'ki', 'opc']}], 'security': {'enabled': True, 'audit_logging': False,
        'auto_clear_keys': True, 'max_cache_time': 60, 'res_star_kdf_mode': 'open5gs_compat',
        'xor_to_milenage_conversion': False}}, sort_keys=False))

ran = config / 'ran'
for name in ['sib', 'rr', 'rb']:
    text = (root / f'sources/srsRAN_4G/srsenb/{name}.conf.example').read_text()
    if name == 'rr':
        text = text.replace('tac = 0x0007;', 'tac = 0x0001;')
    (ran / f'{name}.conf').write_text(text)
(ran / 'enb.conf').write_text('''[enb]
enb_id = 0x19B
mcc = 001
mnc = 01
mme_addr = 10.203.0.20
gtp_bind_addr = 10.203.0.30
s1c_bind_addr = 10.203.0.30
n_prb = 25
[expert]
rrc_inactivity_timer = 300000
[enb_files]
sib_config = /config/ran/sib.conf
rr_config = /config/ran/rr.conf
rb_config = /config/ran/rb.conf
[rf]
device_name = zmq
device_args = fail_on_disconnect=true,tx_port=tcp://*:2000,rx_port=tcp://10.203.0.40:2001,id=enb,base_srate=23.04e6
tx_gain = 80
rx_gain = 40
[log]
all_level = warning
phy_lib_level = none
all_hex_limit = 0
s1ap_level = info
rrc_level = info
filename = /runtime/logs/enb-stack.log
[gui]
enable = false
''')
(ran / 'ue.conf').write_text(f'''[rf]
device_name = zmq
device_args = tx_port=tcp://*:2001,rx_port=tcp://10.203.0.30:2000,id=ue,base_srate=23.04e6
tx_gain = 80
rx_gain = 40
[rat.eutra]
dl_earfcn = 3350
nof_carriers = 1
[rat.nr]
nof_carriers = 0
[usim]
mode = soft
algo = milenage
imsi = {credentials['imsi']}
imei = {credentials['imei']}
k = {credentials['ki']}
opc = {credentials['opc']}
[nas]
apn = internet
apn_protocol = ipv4
force_imsi_attach = true
[gw]
ip_devname = tun_srsue
[log]
all_level = warning
phy_lib_level = none
all_hex_limit = 0
nas_level = info
rrc_level = info
filename = /runtime/logs/ue-stack.log
[gui]
enable = false
''')
(runtime / 'profile.json').write_text(json.dumps({'ciphering': args.ciphering, 'integrity': 'NIA2', 'ue_subnet': str(subnet), 'gateway': gateway, 'ue_ip': ue_ip}))
print('Prepared isolated lab configuration with synthetic credentials (values not displayed).')

(config / 'core' / 'tun-address').write_text(f'{gateway}/{subnet.prefixlen}\n')
