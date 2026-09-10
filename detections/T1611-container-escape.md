# T1611 - Container Escape

| Field | Value |
|---|---|
| ATT&CK | T1611 - Escape to Host |
| Tactic | Privilege Escalation |
| Data source | Falco (runtime); Sysmon EID 1 (the docker command) |
| Severity | Critical |
| Status | validated |

## Hypothesis
A privileged container can break out to the host - here via `--privileged --pid=host` plus
`nsenter -t 1` to enter the host's namespaces, then read/write the host filesystem. Two
detection surfaces: (1) Falco sees the host-file access from container context at runtime;
(2) the launching command itself carries unmistakable flags.

## Detection (SPL)
Runtime (Falco - the flagship container-security tool):
```
index=soclab sourcetype=falco:json | stats count by rule
```
Command signature (Sysmon - catches the launch even if Falco is absent):
```
index=soclab sourcetype=linux:sysmon
| rex field=_raw "<Data Name=\"CommandLine\">(?<cmd>[^<]+)"
| where match(cmd,"docker run.*--privileged") OR match(cmd,"nsenter\s+-t\s+1")
| table _time cmd
```

## Tuning log
| Date | Benign source that fired | Decision | Rationale |
|------|--------------------------|----------|-----------|
| build | (none) | none needed | no containers in baseline |
| note | some CI/monitoring agents run privileged | allowlist known image names/parents | legit privileged containers exist; scope by image |

## Validation
- [x] Fires on: T1611 - Falco "Read sensitive file untrusted" (host /etc/shadow from
      container) + Sysmon `docker run --privileged ... nsenter -t 1` - confirmed the
      container wrote a proof file to the HOST filesystem
- [x] Silent on: `index=soclab_baseline` - 0 rows
- [x] FP count on baseline after tuning: 0

## Known limitations
- Falco's DEFAULT ruleset caught the host-file read but did not raise a dedicated
  "privileged container launched" alert here - enable/add the `Launch Privileged Container`
  and `Change thread namespace` rules for direct coverage of the launch itself.
- An escape via a kernel exploit (not nsenter/privileged) leaves a different footprint -
  this rule covers the common misconfiguration path, not every escape primitive.
- The command-signature half is evadable (rename docker, obfuscate flags); the Falco
  runtime half is the durable detection.
