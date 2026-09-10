# SOC Detection Lab - Linux Attack Simulation to Tuned Detection Logic

Twelve MITRE ATT&CK techniques executed against an isolated Linux host, each turned into
a detection rule **tuned against a recorded benign baseline** and paired with a T1 triage
runbook. Windows/AD coverage is added by writing and tuning rules against public attack
corpora (stated as such, never faked).

The point of this repo is not that the rules fire. It is that each rule has a documented
false-positive story, a stated blind spot, and a runbook a tier-1 analyst could work.

## Why Linux (and why that is a feature)

Almost every entry-level SOC portfolio on GitHub is the same Windows/Sysmon/Atomic-Red-Team
clone. Linux detection labs are rare, and Linux detection engineering is exactly what the
modern cloud/endpoint SOC hires for (see: CrowdStrike Linux sensor roles, any Falco/eBPF
shop). This lab also lets an offensive background become an asset: technique T1068 detects
an exploit the author wrote - detection from the attacker's side of the keyboard.

## Telemetry stack (all three confirmed emitting)

| Sensor | What it gives you | Enterprise relevance |
|--------|-------------------|----------------------|
| **auditd** (Neo23x0 ruleset, 206 rules) | syscall/execve, file access, privilege ops | the Linux SOC baseline; what most shops actually run |
| **Sysmon for Linux** | process/network/file events in the Windows Sysmon schema | rule logic transfers to/from Windows Sysmon |
| **Falco** (modern eBPF, CO-RE) | runtime + container behavioural rules | CNCF standard; the cloud-native detection tool |

## Architecture

Host is a 7.5 GB laptop. The victim VM is tiny (2 GB) and QEMU/KVM-based, so it can run
**alongside** Splunk - no phasing needed like a Windows VM would force.

```
  vm/  (isolated victim - user-mode net, SSH on 127.0.0.1:2222 only)
  +-----------------------------------+
  | Ubuntu 24.04 QEMU/KVM             |
  |   auditd + Sysmon-Linux + Falco   |
  |   Atomic Red Team (Linux atomics) |     collect.sh
  +-----------------------------------+ ---------------> evidence/<label>/
              ^                                              |
              | rollback.sh (snapshot: provisioned-clean)    v  to-splunk.sh
              |                              +-----------------------------------+
              +-- run atomics, timestamp -->| Splunk Free (Docker, 2.5 GB)      |
                                            |   index=soclab                    |
                                            |   index=soclab_baseline           |
                                            +-----------------------------------+
```

## How to run it

```bash
vm/start-vm.sh                 # boot victim (already provisioned)
vm/ssh.sh                      # shell into it
# ... record baseline (see atomics/PLAN.md #00), then run atomics ...
ingest/collect.sh baseline     # pull auditd+sysmon+falco -> evidence/baseline/
ingest/collect.sh T1003.008    # after running that atomic
docker compose up -d           # Splunk at http://localhost:8000
```

## Layout

| Path | What is in it |
|---|---|
| `vm/` | QEMU victim: start/stop/ssh/rollback scripts, cloud-init-provisioned image |
| `cloud-init/` | The unattended provisioning (user-data) - how the sensors got installed |
| `atomics/PLAN.md` | 12 Linux techniques + Windows-corpus strategy + discipline |
| `atomics/RUNLOG.md` | UTC timestamps per atomic - chain of custody |
| `detections/` | One file per technique. `T1003.008` and `_EXAMPLE-T1003.001` are fully worked |
| `docs/` | Runbook template; setup for the two advanced techniques (T1611, T1068) |
| `ingest/` | `collect.sh` (pull telemetry), Splunk ingest guide |
| `evidence/` | Collected corpora (gitignored) |

## Status

| # | Technique | Rule | Tuned | Runbook |
|---|-----------|------|-------|---------|
| Infra | Victim VM + 3 sensors + snapshots | **DONE** | - | - |
| 05 | T1003.008 /etc/shadow access | **worked example** | partial | [ ] |
| 01 | T1059.004 Unix shell | **done** | [ ] | [ ] |
| 02 | T1053.003 Cron persistence | **worked (taught)** | [ ] | [ ] |
| 03 | T1543.002 systemd persistence | **done** | [ ] | [ ] |
| 04 | T1548.001 setuid abuse | **done** | [ ] | [ ] |
| 06 | T1547.006 Kernel module load | **done** | [ ] | [ ] |
| 07 | T1070.003 Clear history/logs | **done** | [ ] | [ ] |
| 08 | T1552.004 SSH key theft | **done** | [ ] | [ ] |
| 09 | T1021.004 SSH lateral | **done** | [ ] | [ ] |
| 10 | T1105 Ingress tool transfer | **done** | [ ] | [ ] |
| 11 | T1611 Container escape | **done** | [ ] | [ ] |
| 12 | T1068 Privesc (own exploit) | **worked example** | [ ] | [ ] |

## Limitations, stated up front

- Splunk **Free**: no scheduled alerting or RBAC; detections run as manual saved searches.
  This is a rule-development environment, not a production SIEM.
- Single host, no directory service - no Kerberos/LDAP techniques. Out of scope by design.
- Atomic Red Team runs technique procedures, not evasive campaigns; rules are validated
  against known-good attack samples, not against an operator actively evading them.
- Windows telemetry is from public corpora, not self-generated - and labelled as such.
