#!/usr/bin/env bash
# Pull the three telemetry streams off the victim into evidence/<label>/
# Usage: ./collect.sh <label>     e.g. ./collect.sh baseline   or   ./collect.sh T1003.008
set -e
L="${1:?usage: collect.sh <label>}"
cd "$(dirname "$0")/.."
SSH="vm/ssh.sh"
OUT="evidence/$L"; mkdir -p "$OUT"
echo "[*] collecting into $OUT (UTC $(date -u +%FT%TZ))"
$SSH 'sudo cat /var/log/audit/audit.log'        > "$OUT/auditd.log"
$SSH 'sudo grep "<Event>" /var/log/syslog || true' > "$OUT/sysmon.xml"
$SSH 'sudo cat /var/log/falco_events.json || true' > "$OUT/falco.json"
wc -l "$OUT"/* 2>/dev/null
echo "[*] done. ingest with ingest/to-splunk.sh $L"
