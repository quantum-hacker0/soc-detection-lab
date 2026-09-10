#!/usr/bin/env bash
# Revert the victim to the clean provisioned state (before any attack tooling ran).
cd "$(dirname "$0")"
./stop-vm.sh; sleep 2
qemu-img snapshot -a provisioned-clean soclab-victim.qcow2
echo "rolled back to provisioned-clean"
./start-vm.sh
