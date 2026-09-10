# Telemetry pipeline - collect, ingest, search

The victim VM (`vm/`) runs three sensors. This directory moves their output into Splunk.

## Live state (already loaded)

| Index | Corpus | Contents |
|-------|--------|----------|
| `soclab_baseline` | 2 min benign admin activity | auditd 4027, sysmon 184, falco 0 |
| `soclab` | 6 attack techniques | auditd 3831, sysmon 222, falco 12 |

Splunk UI: http://localhost:8000  (admin / <from your .env>)

## Scripts

```bash
../vm/start-vm.sh                     # boot the victim
../vm/rollback.sh                     # reset victim to provisioned-clean (before each baseline)
./collect.sh   <label>                # pull auditd+sysmon+falco -> evidence/<label>/
./to-splunk.sh <label> <index>        # ingest a corpus:  to-splunk.sh baseline soclab_baseline
./search.sh    '<SPL>'                # run a detection from the host
```

## Full cycle for a new technique

```bash
../vm/rollback.sh                                     # clean slate
../vm/ssh.sh 'sudo truncate -s0 /var/log/audit/audit.log /var/log/syslog; \
              sudo truncate -s0 /var/log/falco_events.json'
# ... run the atomic (see atomics/PLAN.md), noting UTC time in atomics/RUNLOG.md ...
./collect.sh   T1053.003
./to-splunk.sh T1053.003 soclab
./search.sh 'index=soclab ... your detection ...'    # develop the rule
./search.sh 'index=soclab_baseline ... same rule ...'# TUNE: must be quiet here
```

## Parsing

`../splunk-config/props.conf` (installed in the container) line-breaks each sourcetype:
falco:json one alert per line, linux:audit one record per line, linux:sysmon per `<Event>`.
Re-installed automatically only if you rebuild; if you `docker compose down -v` (wipes
volumes), re-copy it: `docker cp ../splunk-config/props.conf soclab-splunk:/opt/splunk/etc/system/local/`

## Splunk Free limits (state these in the write-up)
- 500 MB/day indexing - fine for bounded lab corpora.
- No scheduled alerting or RBAC - detections run as manual saved searches.
