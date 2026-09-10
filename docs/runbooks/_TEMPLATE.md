# Runbook: <ALERT NAME>

**ATT&CK:** <ID> | **Severity:** <Low/Med/High/Crit> | **Owner:** T1

## What this alert means (plain language)
Two sentences. A tired analyst at 3am is the reader.

## Triage steps
1. Confirm the source process path and signature status.
2. Pivot: what else did `SourceProcessId` do in the surrounding 10 minutes?
3. Is the host in a known maintenance window or admin-tooling scope?
4. Check the account context - service account, admin, or standard user?

## Escalate to T2 when
- <specific, falsifiable condition>
- <specific, falsifiable condition>

## Close as false positive when
- <specific condition, plus what to add to the tuning log>

## Evidence to attach before handoff
Host, account, process tree, timestamps in UTC, the raw event, and what you already ruled out.
