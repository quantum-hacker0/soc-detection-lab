# How I write these detections

Notes to myself on the method, so I stay consistent. A detection rule here is just a search
that returns rows when something bad happened and nothing when it didn't. Every rule in the
lab followed the same five steps.

## The mental model

A Splunk search reads left to right, and each `|` (pipe) hands the results to the next
step - exactly like a shell pipe. You start with everything, then narrow.

```
index=soclab          <- start: all attack events
| <extract fields>    <- pull useful values out of the raw log line
| where <condition>   <- keep only the rows that matter
| table / stats       <- show or count what's left
```

## The five moves (this is the whole skill)

### Move 1 - Find the attack in the raw data
Search the attack index for any word you know the attack used. Look at ONE raw event.
```
index=soclab "/etc/cron.d/" | head 1
```
You are reading the log to see what the attack looks like. Don't write anything yet.

### Move 2 - Pull the fields out
Logs are messy text. `rex` (regular expression extract) grabs a value and names it.
The pattern is always: `rex field=_raw "text before the value(?<yourname>[^<]+)"`
```
| rex field=_raw "<Data Name=\"TargetFilename\">(?<file>[^<]+)"
```
`(?<file>[^<]+)` means "capture everything that isn't a `<`, call it `file`."
You now have a field called `file` you can filter and display.

### Move 3 - Keep only what matters
```
| where like(file,"/etc/cron%")
```
`like(field,"pattern%")` - the `%` is a wildcard. This keeps only cron-file writes.

### Move 4 - THE MOVE THAT MAKES IT A DETECTION: test against the baseline
Run the SAME search on `index=soclab_baseline`. If it returns rows, your rule will
false-positive on normal activity and you must narrow it. If it returns 0, it's clean.
```
index=soclab_baseline sourcetype=linux:sysmon "/etc/cron.d/" | stats count
```
This is the step that separates a real detection from a grep. A rule I haven't run against
the baseline isn't finished.

### Move 5 - Show the result cleanly
```
| table _time who_ran file      (a readable list)     ... or ...
| stats count by who_ran        (a count)
```

## A complete rule, built with the five moves (T1053.003 cron persistence)

```
index=soclab sourcetype=linux:sysmon
| rex field=_raw "<EventID>(?<eid>\d+)"
| rex field=_raw "<Data Name=\"TargetFilename\">(?<file>[^<]+)"
| rex field=_raw "<Data Name=\"Image\">(?<who_ran>[^<]+)"
| where eid=11 AND (like(file,"/etc/cron%") OR like(file,"/var/spool/cron%"))
| table _time who_ran file
```
- `eid=11` = Sysmon "a file was created" event.
- Result: 1 row on the attack (`tee` wrote `/etc/cron.d/soclab-evil`), 0 on baseline.
That 1-vs-0 is a working detection. You just wrote one.

## How to run a search without the web UI
```
ingest/search.sh 'index=soclab sourcetype=linux:sysmon | head 3'
```
Or in the browser at http://localhost:8000 - paste the search into the search bar, set
the time range to "All time" (the lab data is timestamped in the past).

## Field cheat-sheet for this lab's data

**Sysmon** (`sourcetype=linux:sysmon`) - fields live inside `<Data Name="X">value</Data>`:
| You want | EventID | Field to rex |
|----------|---------|--------------|
| a program ran | 1 | Image, CommandLine, ParentImage, User |
| a file was created | 11 | TargetFilename, Image |
| a network connection | 3 | DestinationIp, DestinationPort, Image |

**auditd** (`sourcetype=linux:audit`) - fields are `key=value` in the line:
- `type=SYSCALL syscall=59` = a program executed (execve)
- `exe="..."` the binary, `auid=` the real user, `euid=` the effective user
- `euid=0` while `auid=1000` = a normal user is running as root = privesc signal

**Falco** (`sourcetype=falco:json`) - already parsed JSON, just filter on `rule`:
```
index=soclab sourcetype=falco:json | stats count by rule
```

## Quick pointers per technique

Where each one tends to show up, as a starting point:
- T1543.002 systemd - Sysmon eid=1, `systemctl enable`; exclude `--user` session noise.
- T1552.004 SSH key theft - Sysmon eid=11, key filename created outside `.ssh`.
- T1105 ingress transfer - Sysmon eid=1, curl/wget writing to /tmp (not the tool alone).
- T1070.003 log clearing - auditd, truncate/unlink of log files.
- T1547.006 kernel module - auditd `syscall=finit_module`/`init_module`.
- T1059.004 suspicious shell - Sysmon eid=1, CommandLine with base64 -d or `/dev/tcp`.
- T1021.004 ssh lateral - Sysmon eid=1, outbound ssh client, StrictHostKeyChecking=no.

T1003.008 and T1068 are the most detailed write-ups if I need to remember the structure.
