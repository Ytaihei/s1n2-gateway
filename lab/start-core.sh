#!/bin/bash
set -euo pipefail
python3 /lab/seed.py
ip tuntap add name ogstun mode tun
ip addr add "$(cat /config/core/tun-address)" dev ogstun
ip link set ogstun up
pids=()
cleanup() {
    trap - EXIT TERM INT
    kill "${pids[@]}" 2>/dev/null || true
    wait || true
}
trap cleanup EXIT TERM INT
for nf in nrf scp upf smf ausf udm udr pcf bsf nssf amf; do
    "open5gs-${nf}d" -c "/config/core/${nf}.yaml" > "/runtime/logs/${nf}-console.log" 2>&1 &
    pids+=("$!")
    sleep 0.3
done
wait -n "${pids[@]}"
exit 1
