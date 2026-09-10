# Getting EVTX from the VM into Splunk

Phase 2 - the Windows VM is powered OFF at this point.

## 1. Export on the Windows VM (before shutdown)
```powershell
$out = "C:\export"; mkdir $out -Force
wevtutil epl "Microsoft-Windows-Sysmon/Operational" "$out\sysmon.evtx"
wevtutil epl Security       "$out\security.evtx"
wevtutil epl "Microsoft-Windows-PowerShell/Operational" "$out\powershell.evtx"
```
Copy them to `soc-detection-lab/evidence/` on the host (shared folder or scp).

## 2. Ingest
The compose file mounts `./evidence` read-only at `/evidence` inside the container.
Splunk cannot parse raw .evtx directly - convert to XML first on the host:

```bash
pip install --user evtx            # or: cargo install evtx
evtx_dump -o xml evidence/sysmon.evtx > evidence/sysmon.xml
```

Then one-shot it:
```bash
docker exec -it soclab-splunk /opt/splunk/bin/splunk add oneshot /evidence/sysmon.xml \
  -index soclab -sourcetype "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" \
  -auth admin:<redacted-see-env>
```

Create the index first (once):
```bash
docker exec -it soclab-splunk /opt/splunk/bin/splunk add index soclab \
  -auth admin:<redacted-see-env>
```

## 3. Ingest the baseline into a SEPARATE index
```bash
docker exec -it soclab-splunk /opt/splunk/bin/splunk add index soclab_baseline -auth admin:...
```
Run every rule against `index=soclab_baseline` too. That is the tuning step, and it is
the part that separates this project from every other lab repo on GitHub.

## Splunk Free limits worth knowing
- 500 MB/day indexing. Plenty here; you are ingesting a bounded corpus, not a live feed.
- No auth/roles, no scheduled alerting. Run detections as saved searches manually.
  Note this limitation in your write-up rather than pretending it is a production SIEM.
