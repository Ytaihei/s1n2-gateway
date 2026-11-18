#!/usr/bin/env python3
import json
import time
from pathlib import Path
from pymongo import MongoClient
c = json.loads(Path('/runtime/credentials.json').read_text())
client = MongoClient('mongodb://mongo/open5gs', serverSelectionTimeoutMS=1000)
for _ in range(30):
    try:
        client.admin.command('ping')
        break
    except Exception:
        time.sleep(1)
else:
    raise SystemExit('Lab MongoDB did not become ready')
ambr = {'downlink': {'value': 1, 'unit': 3}, 'uplink': {'value': 1, 'unit': 3}}
doc = {'schema_version': 1, 'imsi': c['imsi'], 'msisdn': [], 'imeisv': [], 'mme_host': [],
       'mm_realm': [], 'purge_flag': [], 'security': {'k': c['ki'], 'opc': c['opc'], 'op': None, 'amf': '8000', 'sqn': 0},
       'slice': [{'sst': 1, 'default_indicator': True, 'session': [{'name': 'internet', 'type': 1,
           'qos': {'index': 9, 'arp': {'priority_level': 8, 'pre_emption_capability': 1, 'pre_emption_vulnerability': 2}},
           'ambr': ambr, 'pcc_rule': []}]}], 'ambr': ambr, 'access_restriction_data': 32,
       'network_access_mode': 0, 'subscriber_status': 0, 'operator_determined_barring': 0,
       'subscribed_rau_tau_timer': 12, '__v': 0}
# This database exists only in the ephemeral lab network.
client.open5gs.subscribers.update_one({'imsi': c['imsi']}, {'$setOnInsert': doc}, upsert=True)
print('Synthetic lab subscriber is ready (values not displayed).')
