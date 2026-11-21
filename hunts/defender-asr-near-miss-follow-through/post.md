# Hunting ASR Near-Misses: Blocked Attempts and the Route Around Them

### Why This Hunt Matters

Attack surface reduction rules stop specific attack steps. Examples include reading LSASS memory, Office starting child processes, PsExec or WMI creating processes, and scripts launching downloaded executables. Every block is a record of an attempt, and in audit mode every event is a record of an attempt that went ahead. In most organisations without Defender for Endpoint nobody reads these records: they stay in the local Defender event log, which is rarely forwarded.

Defender also stores them in its encrypted database, `mpenginedb.db`, in a table called `ProcessBlockHistory`. That table keeps about 90 days, much longer than the roughly two weeks the rest of the database holds. The open-source [osquery-defender-extension](https://github.com/rakeshrm/osquery-defender-extension), built on [Protokol-7's research](https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html), exposes the table with each rule's name attached. That puts three months of attack attempts, across the whole fleet, one query away.

### The Hypothesis

An intruder triggered an ASR rule and then reached the same objective by a route the rule does not cover. Alternatively, the rule was only auditing, and the action went ahead.

### How the Hunt Flows

The first query reads the ASR history on every Windows host and groups it by rule, triggering process, target and mode. Stacked across the fleet, the line-of-business application that trips the Office rule on 400 hosts stands apart from the binary in a user's temp folder that tried to read LSASS on one. An agent separates near-misses from noise. It records each near-miss's time, the objective the blocked action served, and whether the rule was in audit mode. It also suggests confirmed noise for the `asr_noise_processes` parameter, which keeps those processes out of later runs.

A blocked attacker usually tries another way, so four queries look for that route on the near-miss hosts:

- **Credential theft without touching LSASS directly:** comsvcs `MiniDump`, procdump, `reg save` of the SAM, SECURITY and SYSTEM hives, and NTDS or shadow-copy access.
- **Indirect launch:** a script host or LOLBin started through WMI, COM, MMC or the task scheduler instead of from Word.
- **New services:** services running `cmd /c`, PowerShell or a binary from a user-writable folder, the alternative to PsExec.
- **New scheduled tasks:** tasks that run script hosts or user-space binaries.

A second agent puts each host's rows in time order from the ASR event and decides whether the attacker got through. Hosts where they did go to an approval-gated isolation. Where the target was credentials, the action also treats every account that logged on to the host as exposed. Anything unclear goes to an analyst.

### What the Hunt Cannot See

The follow-through steps depend on process creation with command lines, plus service and task creation events. Without them the hunt finds the near-miss but cannot say what happened next, and it routes to a person. Rules that are off record nothing. Events older than about 90 days, and events on rebuilt hosts, are gone. Persistence moved into a WMI event subscription is not covered by any source the hunt reads. The `action` and `taint_reason` codes are undocumented.

### How to Run It

The hunt is a `hunt.md` playbook for Huntbase or any runtime that reads the format. The ASR step is an osquery query that needs the `defender_mpengine` extension loaded on Windows hosts; in Huntbase it runs through Endpoint Control. Set `lookback_days` to cover the time since the oldest near-miss. For rules that only audited on near-miss hosts, the hunt itself is the argument for moving them to enforcement.

Credit for the research behind the extension goes to Protokol-7, whose write-up and tooling decoded `mpenginedb.db`.
