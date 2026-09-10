# T1003.001 - LSASS Memory Access (Credential Dumping)

| Field | Value |
|---|---|
| ATT&CK | T1003.001 - OS Credential Dumping: LSASS Memory |
| Tactic | Credential Access |
| Data source | Sysmon Event ID 10 (ProcessAccess) |
| Severity | High |
| Status | draft / tuned / validated |

## Hypothesis
A process that is not a known Windows security component opens a handle to
`lsass.exe` with read-memory rights. Legitimate credential access is dominated by a
small, enumerable set of processes; anything else reading LSASS is worth an analyst.

## Detection (SPL)
```
index=soclab source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| where TargetImage LIKE "%\\lsass.exe"
| eval ga=tonumber(replace(GrantedAccess,"^0x",""),16)
| where (ga AND 0x0010) != 0            /* PROCESS_VM_READ */
| search NOT SourceImage IN (
    "C:\\Windows\\System32\\wininit.exe",
    "C:\\Windows\\System32\\services.exe",
    "C:\\Windows\\System32\\csrss.exe",
    "C:\\Program Files\\Windows Defender\\MsMpEng.exe")
| stats count min(_time) as first max(_time) as last
        values(GrantedAccess) as access values(CallTrace) as calltrace
        by host, SourceImage, SourceProcessId
| convert ctime(first) ctime(last)
```

## Tuning log
What fired on the baseline and what was done about it - including anything left
un-excluded, and why.

| Date | Benign source that fired | Decision | Rationale |
|------|--------------------------|----------|-----------|
| | MsMpEng.exe (Defender) | excluded | Signed, fixed path, continuous - excluding by full path not filename |
| | | | |

## Validation
- [ ] Fires on: atomic T1003.001-1 (procdump), T1003.001-2 (comsvcs.dll MiniDump)
- [ ] Silent on: `baseline.evtx` (30 min idle + normal use)
- [ ] FP count on baseline after tuning: ___
- [ ] Evasion checked: does it still fire if the attacker renames the binary? (it should -
      the rule keys on target + access rights, not on source filename)

## Known limitations
Every detection has them; worth writing down so the gaps are explicit.
- Handle-only access with `PROCESS_QUERY_LIMITED_INFORMATION` is not covered by design.
- A driver or PPL-bypass dumping LSASS from kernel produces no EID 10.
