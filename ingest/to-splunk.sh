#!/usr/bin/env bash
# Ingest a collected corpus into Splunk.
# Usage: ./to-splunk.sh <label> <index>
#   ./to-splunk.sh baseline    soclab_baseline
#   ./to-splunk.sh attack-run1 soclab
set -e
L="${1:?usage: to-splunk.sh <label> <index>}"; IDX="${2:?need target index}"
cd "$(dirname "$0")/.."
[ -f "$(dirname "$0")/../.env" ] && . "$(dirname "$0")/../.env"; PW="${SPLUNK_PASSWORD:?set SPLUNK_PASSWORD in .env}"
C="docker exec -u splunk soclab-splunk /opt/splunk/bin/splunk"
D="/evidence/$L"   # evidence/ is bind-mounted read-only at /evidence in the container

ingest () { # file sourcetype
  local f="$1" st="$2"
  [ -s "evidence/$L/$(basename $f)" ] || { echo "  skip $st (empty)"; return; }
  $C add oneshot "$D/$(basename $f)" -index "$IDX" -sourcetype "$st" -auth admin:$PW 2>&1 | tail -1
}
echo "[*] ingesting $L -> index=$IDX"
ingest auditd.log  linux:audit
ingest sysmon.xml  linux:sysmon
ingest falco.json  falco:json
echo "[*] done"
