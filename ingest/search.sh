#!/usr/bin/env bash
# Run an SPL search against the lab Splunk from the host.
# Usage: ./search.sh 'index=soclab sourcetype=falco:json | stats count by rule'
PW='<redacted-see-env>'
exec docker exec -u splunk soclab-splunk /opt/splunk/bin/splunk search "$*" \
  -auth admin:$PW 2>/dev/null | grep -v "WARNING:"
