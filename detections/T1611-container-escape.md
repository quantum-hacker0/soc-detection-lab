# T1611 - Container Escape

| Field | Value |
|---|---|
| ATT&CK | T1611 - Container Escape |
| Tactic | Privilege Escalation |
| Data source | Falco (signature use case) |
| Severity | Critical |
| Status | not started |

## Hypothesis
<What behaviour are you claiming is rare-and-bad on a Linux host, and why is the benign
population of it small enough to alert on? Name the sensor and the specific event.>

## Detection (SPL)
```
index=soclab <sourcetype for the sensor above> <...>
```

## Tuning log
Run against `index=soclab_baseline` and record every benign hit.

| Date | Benign source that fired | Decision | Rationale |
|------|--------------------------|----------|-----------|
| | | | |

## Validation
- [ ] Fires on: <atomic test / method from atomics/PLAN.md>
- [ ] Silent on: `index=soclab_baseline`
- [ ] FP count on baseline after tuning: ___

## Known limitations
- <how would an attacker who knows this rule exists evade it?>
