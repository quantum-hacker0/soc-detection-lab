# Execution log

Record every run. UTC. This is your chain of custody and it makes the write-up trivial.

| Date (UTC) | ATT&CK ID | Atomic test | Host | Start | Stop | Notes / observed EIDs |
|------------|-----------|-------------|------|-------|------|-----------------------|
| | | baseline (no attack) | WIN-LAB01 | | | idle + normal use, 30 min |
| | | | | | | |

## Automated run 1 - 2026-09-10T05:22:19Z
| Date (UTC) | ATT&CK ID | Method | Host | Result |
|------------|-----------|--------|------|--------|
| 2026-09-10T05:21Z | baseline | 2min benign admin activity | soclab-victim | evidence/baseline/ |
| 2026-09-10T05:22Z | T1003.008 | cat/cp/awk /etc/shadow | soclab-victim | Falco + auditd |
| 2026-09-10T05:22Z | T1059.004 | base64-decode exec, /dev/tcp | soclab-victim | auditd |
| 2026-09-10T05:22Z | T1070.003 | history -c, clear .bash_history | soclab-victim | auditd |
| 2026-09-10T05:22Z | T1053.003 | crontab + /etc/cron.d evil | soclab-victim | Sysmon FileCreate |
| 2026-09-10T05:22Z | T1548.001 | setuid root bash in /tmp | soclab-victim | auditd + Falco |
| 2026-09-10T05:22Z | T1552.004 | find + copy .ssh keys | soclab-victim | auditd |
