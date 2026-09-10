# KQL detections (Windows / Microsoft Sentinel + Defender XDR)

The `detections/` folder is Linux telemetry I generated and ran through Splunk (SPL). This
folder is the Windows side: the same ATT&CK techniques written in KQL against Microsoft
Sentinel and Defender XDR schemas, tested against a public Windows attack corpus.

I added this because the detection method is the same across platforms - hypothesis, find
the attack in telemetry, write the rule, tune it - but the query language and tables differ.
Porting a few rules was the quickest way to work in KQL and cover Windows techniques the
Linux host can't produce (LSASS, registry Run keys, PowerShell script blocks, etc.).

## Data source (important - read this)

The Windows telemetry here is **not** self-generated. It comes from the public
**EVTX-ATTACK-SAMPLES** corpus (sbousseaden), which ships labelled `.evtx` files per
ATT&CK technique. I parsed the relevant samples to confirm the real event IDs and field
names, and wrote each KQL query against them.

The KQL is written to the **standard Sentinel/Defender table schemas** (`SecurityEvent`,
`Event`, `DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceEvents`). It is **validated
against the sample events' structure, not executed in a live Sentinel tenant** - I don't
have an Azure subscription in this lab. Each file's "Validation" section states exactly what
matched in the sample.

## Linux (SPL) <-> Windows (KQL) technique map

| Tactic | Linux rule (SPL, self-generated) | Windows rule (KQL, public corpus) |
|--------|----------------------------------|-----------------------------------|
| Credential Access | T1003.008 /etc/shadow | T1003.001 LSASS access |
| Defense Evasion | T1070.003 clear logs/history | T1070.001 clear Windows event logs |
| Persistence | T1053.003 cron / T1543.002 systemd / T1547.006 kmod | T1547.001 registry Run key |
| Persistence | (cron) | T1053.005 scheduled task |
| Execution | T1059.004 unix shell (base64/`/dev/tcp`) | T1059.001 obfuscated PowerShell |
| Command & Control | T1105 ingress (curl/wget) | T1105 ingress (bitsadmin/certutil) |

## Reproduce the validation

```bash
# clone the public corpus (not vendored here - it's ~50MB)
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
pip install python-evtx
python3 parse_evtx.py "EVTX-ATTACK-SAMPLES/Credential Access/CA_hashdump_4663_4656_lsass_access.evtx"
# -> confirms EventID 4656/4663, ObjectName lsass.exe, the fields each KQL rule keys on
```

## Files
One per technique, each with: the KQL (Sentinel and Defender variants where both apply),
the exact sample it was validated against, what matched, and known limitations.
