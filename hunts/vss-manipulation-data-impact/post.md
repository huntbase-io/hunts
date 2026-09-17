# Detecting VSS Manipulation and Correlated Data Impact Patterns

Adversaries frequently target the Volume Shadow Copy Service (VSS) for two distinct reasons: creating a point-in-time snapshot to steal the Active Directory database (ntds.dit) or deleting snapshots to prevent recovery during a ransomware event. While simple detection rules for VSS deletion exist, they are often noisy in environments with frequent backup cycles or RMM-driven maintenance. This hunt, inspired by research in "How Attackers Abuse VSS, and How Huntress Detects It" (https://www.huntress.com/blog/vss-abuse-explained), focuses on correlating VSS commands with actual data impact to provide a clearer signal.

### The Hypothesis
We hypothesize that an adversary is actively manipulating Volume Shadow Copies on Windows assets. This activity will manifest as the execution of administrative tools followed by either unauthorized access to sensitive database files or a high volume of file modifications indicative of encryption.

### How the Hunt Flows
The hunt begins by identifying Windows assets within the environment. This scoping phase ensures we are focusing our file and process telemetry analysis on hosts where VSS is likely to be present and used as a vector for credential theft or impact.

Once the scope is defined, we look for the execution of binaries like `vssadmin.exe`, `ntdsutil.exe`, and `wmic.exe` with command line arguments related to shadow copies. Because these tools are often used by legitimate backup software, we apply a baseline to identify rare parent processes. Seeing `vssadmin` spawned by a web server or an unusual user-run process is a much stronger indicator than seeing it run by a known backup agent.

To move from a suspicious command to a confirmed threat, the hunt pivots into parallel corroboration steps. We examine `hb_file_activity` for two specific signals: processes interacting with `ntds.dit` (credential theft) or a surge in file modifications and deletions exceeding a high threshold (ransomware). By requiring this downstream impact, we filter out most legitimate administrative maintenance.

### Limitations and Blind Spots
No hunt is exhaustive. This playbook relies on process execution telemetry and specific command-line strings. If an adversary uses a custom binary that interacts directly with the VSS COM API without calling standard administrative tools, this hunt will not see that interaction. Additionally, the corroboration of mass file activity depends on the retention period of file event logs. If encryption occurred several days after VSS manipulation and the logs have rotated, the correlation will fail.

### How to Run This Hunt
This hunt is packaged as an open `hunt.md` playbook. It can be imported directly into Huntbase or any other `hunt.md`-aware runtime. To execute it, you will need to provide a lookback window for your telemetry and, optionally, a list of specific high-value hosts to prioritize.
