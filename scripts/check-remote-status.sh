#!/bin/sh

# Read-only preflight for the authorized s1n2 integration host.
# Deliberately avoids logs, environment variables, subscriber data, and secrets.

set -eu

REMOTE_HOST="${S1N2_REMOTE_HOST:-taihei-nuc-ubuntu}"
PARENT_DIR="${S1N2_PARENT_DIR:-/home/taihei/open5gs-compose}"
CHILD_DIR="${PARENT_DIR}/s1n2-gateway"

ssh -o BatchMode=yes -o ConnectTimeout=12 "$REMOTE_HOST" sh -s -- "$PARENT_DIR" "$CHILD_DIR" <<'REMOTE'
set -eu

parent_dir=$1
child_dir=$2

printf 'host: '
hostname

printf 'parent: '
git -C "$parent_dir" status --short --branch
printf 'parent HEAD: '
git -C "$parent_dir" rev-parse --short HEAD

printf 'child: '
git -C "$child_dir" status --short --branch
printf 'child HEAD: '
git -C "$child_dir" rev-parse --short HEAD

printf 'submodule pin: '
git -C "$parent_dir" submodule status -- s1n2-gateway

printf 'expected containers:\n'
docker ps --filter name=s1n2 --format '{{.Names}}\t{{.Status}}'

printf 's1n2 SCTP associations: '
docker exec s1n2 sh -c '
  if [ -r /proc/net/sctp/assocs ]; then
    awk "NR > 1 { count++ } END { print count + 0 }" /proc/net/sctp/assocs
  else
    printf "unavailable\n"
  fi
'
REMOTE
