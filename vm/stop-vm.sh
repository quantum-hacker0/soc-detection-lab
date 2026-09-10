#!/usr/bin/env bash
cd "$(dirname "$0")"
[ -f qemu.pid ] || { echo "not running"; exit 0; }
kill "$(cat qemu.pid)" 2>/dev/null && rm -f qemu.pid && echo "stopped"
