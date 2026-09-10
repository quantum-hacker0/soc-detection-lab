# Execution plan - Linux techniques (self-generated telemetry)

Victim: isolated Ubuntu 24.04 QEMU VM (`vm/`). Sensors: auditd (Neo23x0 ruleset,
206 rules), Sysmon for Linux, Falco (modern eBPF). All three confirmed emitting.

Run in this order. Baseline FIRST, always.

| # | ATT&CK ID | Technique | Best sensor | Atomic / method |
|---|-----------|-----------|-------------|-----------------|
| 00 | -        | **Benign baseline** (30 min idle + normal admin use) | all | no attack - see discipline |
| 01 | T1059.004 | Unix shell - suspicious command | auditd execve, Sysmon 1 | ART T1059.004 |
| 02 | T1053.003 | Cron job persistence | Sysmon 11 (/etc/cron*), auditd | ART T1053.003 |
| 03 | T1543.002 | systemd service persistence | auditd, Sysmon 11 | ART T1543.002 |
| 04 | T1548.001 | Setuid/setgid abuse | auditd (perm), Falco | ART T1548.001 |
| 05 | T1003.008 | Read /etc/shadow (credential access) | Falco (default rule), auditd | ART T1003.008 |
| 06 | T1547.006 | Kernel module load (LKM) | auditd (init_module), Falco | ART T1547.006 |
| 07 | T1070.003 | Clear bash history / logs | auditd, Sysmon 11 delete | ART T1070.003 |
| 08 | T1552.004 | SSH private key theft | Sysmon FileCreate /.ssh/, Falco | ART T1552.004 |
| 09 | T1021.004 | SSH lateral movement | auditd, Sysmon 3 (net) | ART T1021.004 |
| 10 | T1105    | Ingress tool transfer (curl/wget payload) | Sysmon 1+3, Falco | ART T1105 |
| 11 | T1611    | **Container escape** | Falco (signature use case) | see docs - needs docker in VM |
| 12 | T1068    | **Local privesc via your own exploit** | auditd, Falco | self-written PoC |

## Windows coverage (optional, not yet done)

Techniques 01-12 are Linux, generated locally. To practice Windows/AD detection without a
Windows VM, ingest a public attack corpus and write rules against it - keeping it clearly
separate from the self-generated Linux data:
- EVTX-ATTACK-SAMPLES (sbousseaden) - labeled EVTX per ATT&CK technique
- OTRF Security-Datasets (Mordor) - Windows + AD attack telemetry as JSON
- Splunk BOTS v3 dataset

## How I keep the results honest

1. **Baseline before any attack.** Roll VM to `provisioned-clean`, use it normally
   30+ min, export that as the baseline corpus. Every rule is tested against it.
2. **Timestamp every atomic** in RUNLOG.md (UTC). Roll back between noisy techniques.
3. **One technique -> one rule -> one runbook.** No bundling.
4. A rule never tested against the baseline is a guess, not a detection.
