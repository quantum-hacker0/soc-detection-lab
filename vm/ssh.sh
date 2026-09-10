#!/usr/bin/env bash
cd "$(dirname "$0")"
exec ssh -i soclab_key -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
     -o LogLevel=ERROR analyst@127.0.0.1 "$@"
