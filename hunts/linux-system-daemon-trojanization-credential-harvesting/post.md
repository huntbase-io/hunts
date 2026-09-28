# Linux System Daemon Trojanization and Credential Harvesting

### Why hunt for trojanized daemons

A recent report from Rapid7, [DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors), describes a campaign where adversaries replace legitimate Linux system binaries with malicious versions. These trojanized daemons log credentials and monitor process health to maintain persistence. Detecting these changes via simple file integrity monitoring often fails or generates excessive noise because legitimate system updates frequently modify these same paths.

### The Hypothesis

An adversary has established long-term persistence and credential harvesting by replacing legitimate Linux system daemons with trojanized versions that log passwords and monitor process health. The attacker targets edge-facing applications to gain initial access before deploying these persistent toolkits.

### How the Hunt Flows

The first phase focuses on lead discovery using the hb_file_activity surface. The query searches for specific encrypted log paths and stager configuration files associated with the Ted and CurlRAT toolkits, such as /tmp/jasper-log or specific hidden paths in /var/lib/snapd/. This step acts as a high-confidence trigger. If an analyst confirms these leads, the hunt moves into a broader expansion phase.

The expansion phase runs two parallel pivots. First, it performs a fleet-wide stack-count of binary hashes for common system daemons like sshd, crond, and agetty using hb_process_activity. The goal is to identify SHA256 hashes that appear on only one or two hosts, which suggests a non-standard or modified binary. Simultaneously, the hunt queries hb_vulnerability_finding to identify hosts running unpatched edge applications like HAProxy or vulnerable versions of polkit.

In the final stage, an analyst correlates these three signals. A host showing a rare daemon hash, known toolkit artifacts, and a high-severity edge vulnerability provides high-confidence evidence of compromise. This layered approach ensures that we only investigate binary variations that occur in a suspicious context.

### What this hunt cannot see

This hunt faces two primary blind spots. First, it relies on file and process telemetry within a specific lookback window. If the adversary trojanized the system months ago and the initial file creation events have rotated out of the telemetry retention, the lead discovery step will return no results. In such cases, the hunt relies entirely on the rarity of the process hash.

Second, the effectiveness of stack-counting depends on the agent's ability to hash system daemons. If the endpoint security configuration excludes standard system paths from hashing to save performance, the hunt cannot identify trojanized outliers. 

### How to run the hunt

This hunt is published as an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. The playbook includes the necessary SQLite queries to baseline your fleet and the logic to gate the investigation, preventing unnecessary overhead on your security stack. Because this hunt targets system-level persistence, we recommend running it as a periodic check on all Linux-based edge infrastructure.
