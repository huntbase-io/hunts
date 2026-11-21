# Hunting Defender Weakening: Tamper Protection, ASR Rules and Exclusions

### Why This Hunt Matters

Before ransomware runs, the operator usually turns Microsoft Defender down. The moves are familiar: an exclusion for the staging folder, ASR rules switched to audit, Tamper Protection off, or the service stopped. Each one is also ordinary administration when it arrives through Group Policy or Intune, so a rule on any one of them either fires all day or is tuned until it never fires.

Defender keeps its own record of some of this. In November 2026 [Protokol-7 showed](https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html) that the engine's encrypted database, `mpenginedb.db`, stores the engine's view of Tamper Protection and the ASR rule state changes it applied. On their test machine they recovered a Tamper Protection record set to off. The open-source [osquery-defender-extension](https://github.com/rakeshrm/osquery-defender-extension) decrypts that database on each host and exposes it as `defender_mpengine_*` tables, so the question can be asked across a fleet.

### The Hypothesis

An operator with administrative rights has weakened Defender on a Windows host by hand, on one host rather than through fleet policy, before running tooling or ransomware.

### How the Hunt Flows

The hunt opens with the engine's state on every host. Did the database decrypt? When did the engine last write an attack-scoring record or a path tag? Is Defender the active, up-to-date antivirus according to Windows Security Center? A busy host whose newest record is days old has an engine that stopped recording.

Five queries then run side by side. Two read the database: the Tamper Protection state the engine persisted, and every ASR rule state change, counted per rule and state. The third lists every exclusion configured now, local and policy, from the registry, which osquery can read because it runs as SYSTEM. The last two use ordinary telemetry: writes to Defender's policy keys with the writing process, and the commands operators use, such as `Set-MpPreference -ExclusionPath`, `MSFT_MpPreference` over WMI, `MpCmdRun -RemoveDefinitions` and `sc stop WinDefend`.

The comparison across the fleet is the core of the hunt. A policy rollout puts the same ASR state or the same exclusion on hundreds of hosts at once, written by the Group Policy or MDM client. An operator's change appears on one host, written by PowerShell or `reg.exe`. An agent sorts the changes on that basis and names the hosts changed by hand.

For those hosts the hunt looks for what weakening is usually for. It checks for binaries running from user-writable or excluded folders, and for shadow-copy, backup, boot-recovery and log-clearing commands. It also reads Defender's own ransomware detections and the files it was tracking for rollback. A second agent builds a timeline per host. Confirmed hosts go to an approval-gated action, which preserves the `Scans` folder first, then isolates the host and restores protection. Everything unclear goes to an analyst.

### What the Hunt Cannot See

Microsoft does not document the values stored for Tamper Protection and ASR state, so they are read as stored and compared against hosts known to be correct. Protokol-7 also notes that a Tamper Protection record cannot be tied to an attacker on its own. Exclusions are not in `mpenginedb.db`. The registry shows them, but its timestamp is per key, so without registry change telemetry an exclusion can be seen but not dated. A host without the extension, or one where another antivirus is primary and Defender is passive, returns nothing or a stale database, which this hunt cannot tell apart from a host that was tampered with.

### How to Run It

The hunt is a `hunt.md` playbook for Huntbase or any runtime that reads the format. The Defender steps are osquery queries that need the `defender_mpengine` extension loaded by osqueryd on Windows hosts. In Huntbase they run through Endpoint Control; on another osquery fleet manager they run as written. Run it across every Windows host, because the fleet comparison is what makes it work. Afterwards, schedule the extension's pack queries for Tamper Protection and ASR state with `removed: true` so future changes are logged as they happen.

Credit for the research behind the extension goes to Protokol-7, whose write-up and tooling decoded `mpenginedb.db`.
