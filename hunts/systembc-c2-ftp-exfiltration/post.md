# Hunting SystemBC C2 and WinSCP Exfiltration

### Why this hunt

The DFIR Report recently published "Blurring the Lines" (https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs/), which describes a campaign involving multiple ransomware affiliates. These groups often share techniques, such as staging SystemBC in predictable locations. This malware is a proxy, allowing attackers to tunnel traffic into the environment or exfiltrate data. We designed this hunt to find these beachheads before the final ransomware deployment.

### The Hypothesis

An adversary stages SystemBC payloads in the Public Music directory and executes them via Rundll32 using the Reset export. After establishing persistence, the adversary uses WinSCP to perform unencrypted FTP exfiltration to known affiliate infrastructure.

### How the Hunt Flows

The hunt begins with a high-fidelity process execution check. The first query searches for Rundll32 processes that load DLLs from the Public Music directory. We specifically look for the string "reset" in the command line, as this export is a known marker for SystemBC initialization. This step identifies the specific hosts that require deeper inspection.

The second phase transitions from the endpoint to the network surface. The hunt fans out into two parallel paths. One path checks for egress to a list of hardcoded C2 IP addresses associated with SystemBC and SectopRAT. The other path looks for any outbound traffic on port 21 or any network activity originating from the WinSCP process. By filtering these network queries to only the hosts identified in the first step, we reduce noise and focus on compromised systems.

The final phase is the triage and correlation step. An analyst reviews the results from both the process and network queries. The goal is to find a direct link: did the host running the suspicious DLL also initiate the FTP or C2 connections? This correlation is what turns a broad search into a verified incident. The playbook then guides the user through isolating the host and collecting forensic artifacts like WakeWordEngine.dll.

### What this Hunt Cannot See

The hunt has two primary blind spots. First, it relies on a set of known C2 IP addresses. If the adversary switches to new infrastructure or uses domain-based C2 that hides behind legitimate cloud providers, the IP filter will not catch the traffic. Second, point-in-time endpoint telemetry can miss short-lived events. If an adversary performs a very rapid exfiltration and closes WinSCP before the next polling interval, the network connection might not be recorded by some EDR surfaces.

### Why this is a Hunt

This is not a simple detection because the components, like WinSCP or Rundll32, are often legitimate. We use the specific staging path in Public Music as a pivot point. The hunt requires an analyst to confirm the relationship between the staging activity and the network egress. This provides a higher level of confidence than a standalone alert on FTP traffic.

### How to Run it

This hunt is an open hunt.md playbook. You can import it into Huntbase or any other hunt.md-aware runtime. It uses standard SQL-based queries that target process and network activity tables. By adjusting the lookback_days parameter, you can scan your environment for historical evidence of this affiliate activity.
