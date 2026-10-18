# Hunting Akira Lateral Access and Security Software Disruption

### Why This Hunt Matters

Recent analysis from Huntress in [Up a Creek Without a Command Line: Mapping an Akira Ransomware Attack](https://www.huntress.com/blog/mapping-akira-ransomware-attack) details how Akira affiliates move laterally and blind defenses. These actors often skip complex exploits in favor of simple RDP sessions and manual service disruption. If an analyst only looks for service stops or only looks for RDP, the signal disappears into the noise of daily administration. This hunt correlates these events to find the intrusion before the adversary reaches their final objective.

### The Hypothesis

An adversary gains lateral access to a target host via RDP. Once they establish a session, they disable security software to avoid detection and then perform credential dumping from staging directories like C:\PerfLogs.

### How the Hunt Flows

The first phase scopes the environment for inbound RDP connections. It specifically searches for the workstation name C1IFRYXI, which has been associated with Akira activity, or high-volume remote interactive logins from other external sources. This step identifies the potential entry points and sets the scope for deeper investigation.

Once the hunt identifies high-risk hosts, it runs two parallel checks. One query looks for the cessation or disablement of Bitdefender services, a common target for Akira blinding efforts. The second query identifies rare binaries executing from C:\PerfLogs or Temp directories. Threat actors often use these locations to stage tools like ProcDump for memory harvesting.

An automated agent then triages the results. It builds a host-by-host timeline, looking for a specific sequence: a remote login followed shortly by security service disruption and the execution of a staging tool. This correlation distinguishes an active compromise from routine server maintenance.

### Blind Spots

This hunt relies on Service Control Manager (SCM) telemetry to detect service stops. If an adversary kills the security process directly or uses registry modifications to prevent the service from starting after a reboot, the specific SCM event may not trigger. Additionally, the hunt focuses on C:\PerfLogs and Temp directories for staging. While common for Akira, an adversary who uses a deeply nested or randomized user profile directory may evade the path-specific filters unless the binary is rare enough to be caught by the prevalence check.

### How to Run the Hunt

We provide this hunt as an open-source `hunt.md` playbook. This format allows you to run the entire investigation as code, importing it directly into Huntbase or any `hunt.md`-aware runtime. It uses standard SQL for telemetry analysis and incorporates automated triage steps to reduce manual workload. If the agent finds a high-confidence match for the Akira pattern, the playbook provides an action to isolate the host immediately to prevent further exfiltration or encryption.
