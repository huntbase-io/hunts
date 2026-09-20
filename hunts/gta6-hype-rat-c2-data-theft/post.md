# Hunting for RATs and Infostealers in GTA VI Malware Bundles

### The Threat of GTA VI Hype

Huntress recently detailed how adversaries exploit the anticipation for Grand Theft Auto VI in their report [Grand Theft Auto VI hype leads to malware](https://www.huntress.com/blog/fake-gta6-download-malware-analysis). Attackers distribute fake installers that bundle functional malware, including NJRAT and DCRAT, to gain remote access and steal credentials from unsuspecting users.

### The Hypothesis

An adversary uses Grand Theft Auto VI hype to deploy RATs and infostealers. These tools use ngrok tunnels for command and control and Discord webhooks for credential exfiltration. The malware typically initiates from user-writable temporary directories to bypass folder permissions and stay within the user context.

### How the Hunt Flows

The hunt begins by scoping execution. A query against `hb_process_activity` identifies every process launching from `%TEMP%` or `C:\Users\Default`. These paths represent the primary execution stages for the reported malware bundle. This step produces a broad list of candidates, as many legitimate installers also run from these locations.

To isolate the threat, the hunt applies a prevalence filter. It stack-counts the discovered binaries across the fleet and keeps only those appearing on three or fewer hosts. This rarity signal separates unique malware variants from common enterprise software and routine updates.

In the final phase, the hunt correlates these rare processes with network activity. It checks for outbound connections to ngrok infrastructure, specific malicious IPs, or Discord. This step confirms the command-and-control behavior and identifies potential exfiltration events. An analyst or agent then triages the overlap between rare execution paths and suspicious network destinations to provide a final verdict.

### Blind Spots

This hunt relies heavily on network telemetry. If a host lacks `hb_network_connection` logs, the hunt only flags rare binaries without confirming C2 activity, which increases the false positive rate. Additionally, without TLS inspection for `hb_http_activity`, an analyst identifies connections to Discord webhooks but cannot confirm exactly which credentials or files the adversary exfiltrated.

### How to Run This Hunt

We provide this hunt as an open `hunt.md` playbook. This format allows you to run the logic directly in Huntbase or any other `hunt.md`-aware runtime. It uses a 14-day lookback period by default to capture activity following major game announcements or leaks. You can adjust the IP and domain parameters as new infrastructure is identified in your environment.
