# T1105 - Ingress Tool Transfer

| Field | Value |
|---|---|
| ATT&CK | T1105 - Ingress Tool Transfer |
| Tactic | Command and Control |
| Data source | Sysmon EID 1 (ProcessCreate) |
| Severity | Medium |
| Status | validated |

## Hypothesis
Attackers pull second-stage tooling with `curl`/`wget`. But admins use those tools
constantly, so the tool alone is NOT a signal - the baseline proves it (curl fires in both
indexes). The signal is the DESTINATION: a download saved into `/tmp`, `/dev/shm`, or a
hidden dotfile is staging, not a connectivity check (baseline wrote to `/dev/null`).

## Detection (SPL)
```
index=soclab sourcetype=linux:sysmon
| rex field=_raw "<EventID>(?<eid>\d+)"
| rex field=_raw "<Data Name=\"Image\">(?<img>[^<]+)"
| rex field=_raw "<Data Name=\"CommandLine\">(?<cmd>[^<]+)"
| where eid=1 AND match(img,"/(curl|wget)$") AND match(cmd,"-[oO]\s*(/tmp/|/dev/shm/|\S*/\.)")
| table _time cmd
```

## Tuning log
| Date | Benign source that fired | Decision | Rationale |
|------|--------------------------|----------|-----------|
| build | `curl -s -o /dev/null http://...` (connectivity checks) | excluded by requiring a suspicious `-o` target | writing to /dev/null is not staging |
| key insight | curl/wget alone fired in BOTH indexes | never alert on the tool; alert on the destination | admins download things all day |

## Validation
- [x] Fires on: T1105 (`curl -o /tmp/.stage1`, `wget -O /tmp/.stage2`) - 2 rows
- [x] Silent on: `index=soclab_baseline` (curl-to-/dev/null excluded) - 0 rows
- [x] FP count on baseline after tuning: 0

## Known limitations
- An attacker who downloads to their home dir or a legit-looking path evades the location
  filter. A stronger version correlates the download with the downloaded file being
  executed shortly after (join EID 1 download -> EID 1 execute of the same path).
- Piping directly to a shell (`curl url | bash`) writes no file - covered instead by the
  T1059.004 suspicious-shell rule. Detections overlap on purpose (defense in depth).
