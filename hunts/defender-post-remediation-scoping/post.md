# Hunting After Defender Remediates: What Changed and Where Else It Is

### Why This Hunt Matters

When Defender reports a threat as remediated, the ticket usually closes. But malware rarely lands on one machine only. On other hosts a slightly different variant, an exclusion, or the attacker's own clean-up may have kept it from being detected. The remediated host is the best lead available, and it is rarely used.

Defender's encrypted database, `mpenginedb.db`, holds what is needed to follow that lead. [Protokol-7 showed](https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html) that its hash cache keeps SHA-256, SHA-1 and MD5 values with MFT references for files real-time protection scanned, and that these entries outlive the files. That makes the cache useful when an attacker has deleted their tools. The database also holds the engine's threat records, plus two remediation caches: the registry values and the system files Defender changed during remediation, with the values before and after. The value before is what the malware wrote. The open-source [osquery-defender-extension](https://github.com/rakeshrm/osquery-defender-extension) exposes all of these as osquery tables.

### The Hypothesis

Malware that Defender remediated on one host also reached other hosts. On those hosts Defender either did not detect it or the attacker deleted it first, and its hashes and persistence can be recovered from Defender's own records.

### How the Hunt Flows

The hunt starts from Defender's remediations in the window, taken from forwarded detections. On those hosts, three queries read what the malware changed. The first reads the engine's threat records and the executables it saw dropped and run. The second reads the registry values remediation put back, with the malicious data. The third reads the system files remediation replaced, with infected and clean hashes. An agent turns these into a list of hashes and registry value names. It also flags any host where a restored value carries the malicious data again, which means remediation did not hold.

The analyst pastes those values in, and four queries sweep the whole estate:

- **Defender's hash cache on every host,** which finds hosts that held the file even after it was deleted.
- **Process telemetry,** for hosts where the file ran.
- **Registry telemetry,** for the same persistence values.
- **A count of rare autostart values across the fleet,** which catches persistence that was renamed.

A second agent sorts each host into present, past or none. Hosts where the malware is still present go to an approval-gated action that isolates and rescans them. Hosts found only in the hash cache go to an analyst to trace through the MFT and USN journal.

### What the Hunt Cannot See

The two remediation caches were empty on every host the extension has been tested on. Their columns follow the live schema, but no real row has been decoded yet, so those steps are best effort. The hash cache stores a volume serial and MFT entry, not a path. It covers only files real-time protection scanned, and only for about two weeks. Without Defender detections in the SIEM, the scoping step is empty, and the threat-record step should run across the estate instead.

### How to Run It

The hunt is a `hunt.md` playbook for Huntbase or any runtime that reads the format. The Defender steps are osquery queries that need the `defender_mpengine` extension loaded on Windows hosts; in Huntbase they run through Endpoint Control. Run it after any remediation of a trojan, backdoor or hacktool. Fill `artefact_hashes` and `persistence_value_names` from the agent's output before the fleet sweep. Keep those values with the incident so the sweep can be repeated.

Credit for the research behind the extension goes to Protokol-7, whose write-up and tooling decoded `mpenginedb.db`.
