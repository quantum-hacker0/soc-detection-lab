#!/usr/bin/env bash
# Boot the isolated lab victim. User-mode networking: the VM can reach the internet
# for provisioning, nothing on your LAN can reach the VM, and SSH is bound to
# loopback only (127.0.0.1:2222).
set -e
cd "$(dirname "$0")"
[ -f qemu.pid ] && kill -0 "$(cat qemu.pid)" 2>/dev/null && { echo "already running (pid $(cat qemu.pid))"; exit 0; }
qemu-system-x86_64 \
  -enable-kvm -cpu host -smp 2 -m 2048 \
  -drive file=soclab-victim.qcow2,if=virtio,format=qcow2 \
  -drive file=seed.iso,if=virtio,format=raw,readonly=on \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=n0 \
  -display none -serial file:console.log \
  -qmp unix:qmp.sock,server,nowait -pidfile qemu.pid -daemonize
echo "booted. pid $(cat qemu.pid)  ssh: ssh -i soclab_key -p 2222 analyst@127.0.0.1"
