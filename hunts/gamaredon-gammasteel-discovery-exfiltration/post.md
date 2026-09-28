# Hunting Gamaredon Gammasteel Orchestration and S3 Data Exfiltration

### Why now

Recent analysis from Sekoia in [FSB’s matryoshka #3/3: Gamaredon's Gammasteel Infostealer](https://www.sekoia.com/blog/fsbs-matryoshka-3-3-gamaredons-gifts-that-keeps-unpacking-gammasteel) details the modular nature of the Gamaredon Group's toolkit. Gammasteel acts as the primary document stealer, relying on a PowerShell-based orchestrator to maintain a regular heartbeat of discovery and theft. While standard detections might flag the persistence mechanism, this hunt focuses on the operational logic that triggers document scanning and exfiltration.

### The hypothesis

The adversary uses a recurring PowerShell timer to discover documents across user profiles and local/network drives, then exfiltrates them to an S3-compatible storage endpoint. The adversary schedules this activity every hour (3.6 million milliseconds) to ensure a steady stream of data from the victim's environment while minimizing the process footprint when the scanner is idle.

### How the hunt flows

The first query searches script block activity for the specific orchestrator logic. The adversary defines a timer with a precise millisecond interval. The query scans for this interval or a known internal function name used by the stealer. Finding these script blocks identifies hosts where the stealer is active even if the persistence registry keys were missed by automated tools.

Next, the hunt fans out to look for the secondary effects of a triggered scan. The adversary uses WMI queries to enumerate user profiles and logical disks. Because these WMI classes appear in legitimate administrative scripts, the hunt applies a prevalence filter. It isolates commands appearing on three or fewer hosts, separating automated malware discovery from organization-wide IT tasks.

Simultaneously, the hunt checks for network traffic to known S3-compatible storage providers. The adversary currently uses tebi.io for data staging. A match between a PowerShell process and these DNS resolutions on a host already flagged for timer-based scripts provides high confidence of an active infection. 

In the final stage, an analyst reviews the collected script content and file access history. If the evidence confirms document theft, the analyst triggers an isolation action to stop the exfiltration and preserves the local registry for deeper forensic analysis of the payload staging.

### Blind spots and limitations

This hunt depends on PowerShell Script Block Logging (Event ID 4104). If an organization does not collect full script text, the initial scoping step will fail to find the orchestrator logic. The network discovery phase relies on a static list of S3 providers. If the adversary rotates to a different cloud storage provider or uses a custom proxy, the DNS query will not find the exfiltration activity. 

### How to run it

This hunt is available as an open-source `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any compatible runtime that parses markdown-based queries. Because this is a hunt, it prioritizes broad visibility and analyst triage over rigid blocking. It is best used for periodic sweeps of sensitive workstations where document confidentiality is a priority.
