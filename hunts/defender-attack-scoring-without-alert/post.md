# Hunting the Processes Defender Scored but Never Alerted On

### Why This Hunt Matters

Microsoft Defender reasons about more than it reports. For each process, its behaviour monitoring keeps a running list of the ATT&CK techniques it has attributed, such as T1003.001 against a renamed `procdump` or T1547.001 against a `rundll32`. It raises a detection only when the combined score crosses a threshold. Everything below that line is never shown, in Protection History or anywhere else.

[Protokol-7 found](https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html) that these attributions live in the attack-scoring queues of Defender's encrypted database, `mpenginedb.db`, keyed by process ID and start time. The open-source [osquery-defender-extension](https://github.com/rakeshrm/osquery-defender-extension) decrypts the database and exposes the queues as an osquery table. For the many Windows fleets that run Defender Antivirus without Defender for Endpoint, this is the only behavioural sensor they have, and its sub-threshold judgement was previously thrown away.

### The Hypothesis

An intruder's tooling did something Defender noticed (credential access, injection, persistence or defence evasion) and stayed below the alert threshold, so nothing reached Protection History or the SIEM.

### How the Hunt Flows

The first query reads the queues on every Windows host. For each process it returns the techniques Defender attributed or that the process inherited from its parent, how many fall in a list of high-signal techniques, and the running process's path and command line where the PID and start time still match. The hunt stacks the image and technique set across the fleet. An updater scored for the same techniques on 3,000 hosts drops away, and a binary in `AppData` scored for T1003.001 on one host stands out.

Three queries then ask whether Defender said anything about each process. The host's own threat queue shows the behaviour detections the engine named against specific PIDs. The low-fidelity queue shows files sent for a cloud verdict; Protokol-7 found hashcat modules there. Forwarded Defender detections show what reached the SIEM. An agent keeps only the scored processes with no alert of any kind and ranks them.

For those, the hunt rebuilds context from ordinary telemetry: the parent, command line, user and hash of each process, and the files it wrote. A `.dmp` file written by a process Defender scored for LSASS access settles the question quickly. A second agent gives a verdict per process. Malicious ones go to an approval-gated action that copies the `Scans` folder and a memory image before isolating the host. Unclear ones go to an analyst.

### What the Hunt Cannot See

The technique queues keep entries for about an hour. A live run sees only the last hour; to hunt over days, schedule the extension's `defender_mpengine_process_techniques` pack query every 30 minutes and run the triage over its results. Without Defender detections in the SIEM, "never alerted" rests on the host's own threat queue alone. Microsoft does not document how techniques are attributed or where the threshold sits, so every row is treated as Defender's opinion, a lead rather than proof. Processes that have exited no longer join to the live process table and need process history from other telemetry.

### How to Run It

The hunt is a `hunt.md` playbook for Huntbase or any runtime that reads the format. The Defender steps are osquery queries that need the `defender_mpengine` extension loaded on Windows hosts; in Huntbase they run through Endpoint Control. Run it often. Keep the benign image and technique pairs it finds as a suppression list so each run gets quieter.

Credit for the research behind the extension goes to Protokol-7, whose write-up and tooling decoded `mpenginedb.db`.
