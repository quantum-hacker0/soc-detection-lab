# soc-detection-lab

A small home lab for writing and testing detection rules against Linux attack telemetry.
I run known attack techniques against an isolated VM, collect what auditd, Sysmon for
Linux, and Falco record, and write Splunk searches that catch each one. Every rule gets
checked against a recording of normal activity too, so I know it isn't just matching noise.

I built this because I wanted to actually understand what an attack looks like in logs,
rather than reading about it. Writing the detection is what forced me to actually learn the telemetry.

## Setup

Everything runs on one laptop (Ubuntu host, 8 GB RAM). The victim is a throwaway QEMU/KVM
VM; Splunk Free runs in Docker on the host.

```
  vm/  (isolated Ubuntu 24.04 victim, user-mode net, SSH on 127.0.0.1:2222)
    auditd (Neo23x0 rules) + Sysmon for Linux + Falco (eBPF)
    Atomic Red Team
        |
        |  collect.sh  ->  evidence/<label>/  ->  to-splunk.sh
        v
  Splunk Free (Docker):  index=soclab (attacks)   index=soclab_baseline (normal)
```

The VM is provisioned by cloud-init (`cloud-init/user-data`) so it's reproducible, and I
snapshot a clean state (`vm/rollback.sh`) to reset before recording a fresh baseline.

## Sensors

- **auditd** with the Neo23x0 ruleset - syscalls, execve, file access, privilege ops.
- **Sysmon for Linux** - process/network/file events, same schema as Windows Sysmon.
- **Falco** (modern eBPF) - runtime and container behaviour rules.

Different techniques surface best in different sensors, which is half the point of running
all three.

## Running it

```bash
vm/start-vm.sh                          # boot the victim
vm/rollback.sh                          # reset to clean before a baseline recording
vm/ssh.sh                               # shell in; run an atomic (see atomics/PLAN.md)
ingest/collect.sh <label>               # pull the three logs into evidence/<label>/
ingest/to-splunk.sh <label> <index>     # load into Splunk
ingest/search.sh 'index=soclab ...'     # run a detection
```

New to SPL? `docs/writing-detections.md` walks through how I approach a rule from scratch.

## Layout

| Path | Contents |
|---|---|
| `vm/` | QEMU victim - start/stop/ssh/rollback scripts |
| `cloud-init/` | Unattended provisioning (how the sensors get installed) |
| `atomics/PLAN.md` | The techniques and how I run them |
| `atomics/RUNLOG.md` | What I ran and when (UTC) |
| `detections/` | One file per technique: hypothesis, SPL, tuning notes, limitations |
| `docs/` | SPL walkthrough, runbook template, setup notes for the container/exploit tests |
| `ingest/` | collect / ingest / search helpers |
| `evidence/` | Collected logs (gitignored) |

## Techniques covered

Credential access, persistence, privilege escalation, defense evasion, execution, lateral
movement, and C2 - 12 in total (see `atomics/PLAN.md`). Two go a bit further than atomics:
a privileged-container escape (T1611) and a setuid PATH-hijack privesc I wrote myself
(T1068), so I could build the detection against something I understood end to end.

## Notes and limitations

- Splunk Free has no scheduled alerting or RBAC, so rules run as manual searches. Fine for
  developing and testing them; not a production SIEM.
- Single host, no directory service - so no Kerberos/LDAP techniques here.
- Atomic Red Team runs the technique procedure, not an operator actively evading detection.
  Rules are tested against known-good attack samples.
- `history -c` turned out to be a genuine blind spot (it's a shell builtin - no process, no
  syscall). Noted in the T1070.003 file; it needs an explicit auditd file watch.
- A few rules detect the launching command rather than the underlying action, because my
  Sysmon config doesn't watch every path. Noted per rule where it applies.
