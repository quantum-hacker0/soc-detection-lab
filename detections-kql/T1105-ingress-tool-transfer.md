# T1105 - Ingress Tool Transfer (Sentinel / KQL)

Same technique as the Linux rule (T1105). There the signal was curl/wget writing to /tmp;
on Windows it's LOLBins (bitsadmin, certutil) pulling a payload, or BITS transfer events.

| Field | Value |
|---|---|
| ATT&CK | T1105 - Ingress Tool Transfer |
| Platform | Defender XDR (DeviceProcessEvents) / Sentinel (BITS-Client Operational) |
| Sample | EVTX-ATTACK-SAMPLES: `Persistence/persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx` |

## KQL - Defender XDR (LOLBin downloaders)
```kql
DeviceProcessEvents
| where FileName in~ ("bitsadmin.exe", "certutil.exe", "curl.exe")
| where ProcessCommandLine has_any ("/transfer", "-urlcache", "urlcache", "http://", "https://")
| where ProcessCommandLine has_any ("\\Temp\\", "\\Users\\Public\\", "\\AppData\\", "\\ProgramData\\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## KQL - Sentinel (BITS transfer job created)
```kql
Event
| where Source == "Microsoft-Windows-Bits-Client" and EventID in (3, 59, 60)
| project TimeGenerated, Computer, RenderedDescription
```

## Validation
- Against the sample: 6 events in the BITS-Client Operational log (EventIDs 3/59/60) from a
  `bitsadmin` transfer named `backdoor` run by `IEWIN7\IEUser` - a BITS-based download used
  for persistence/staging.
- Same logic as the Linux rule: the tool (bitsadmin/certutil) is legitimate; the signal is
  the download destination and context, not the tool alone.

## Notes
- certutil/bitsadmin have legitimate uses; the path filter (`\Temp\`, `\Public\`) is the
  tuning lever, exactly like requiring a suspicious `-o` target on the Linux curl/wget rule.
- Modern operators use `Invoke-WebRequest`/`curl.exe` - the FileName list should be kept
  current as tradecraft shifts (noted the same way on the Linux rule).
