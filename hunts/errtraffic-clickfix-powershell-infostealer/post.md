# Hunting for ErrTraffic Infostealer and ClickFix PowerShell Activity

### Why now?

Sekoia recently published research titled "Unveiling ErrTraffic: inside a growing ClickFix malware distribution framework" (https://www.sekoia.com/blog/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework). The report details a high-conversion social engineering scheme where attackers trick users into pasting and running PowerShell commands to "fix" browser errors. Once executed, these commands download infostealers that harvest browser credentials. Because the framework uses blockchain-based domain resolution for its C2, infrastructure rotates quickly, making traditional static indicators less effective than behavioral hunting.

### The Hypothesis

An intruder tricks a user into running a PowerShell command via a ClickFix lure. This command downloads an infostealer that harvests credentials from browser data stores and connects to blockchain-resolved C2 domains. The adversary relies on the user's local permissions to execute the payload and access sensitive files stored in the user profile.

### How the hunt flows

The hunt begins with a scoping phase using the `hb_dns_activity` surface. A query identifies hosts that have resolved known ErrTraffic C2 domains or blockchain-derived infrastructure within the last 14 days. This reduces the search space for more intensive behavioral queries. If the attacker uses new domains not in the provided list, the subsequent phases still run across the broader estate to find the activity.

In the second phase, the hunt executes two parallel queries to find behavioral evidence. The first query searches the `hb_process_activity` surface for PowerShell executions containing specific ClickFix download markers. The second query monitors the `hb_file_activity` surface for non-browser processes accessing browser credential files like "Login Data" or "Cookies". It baselines these accesses to exclude legitimate browser activity and focus on rare, suspicious reads.

Finally, an agent or analyst correlates these findings in the triage phase. By joining the DNS resolutions, the PowerShell command-line evidence, and the file access logs, the hunt establishes a complete infection chain. If a host shows evidence of both the lure and the harvesting, the playbook provides an action to isolate the host and revoke cloud sessions.

### What this hunt cannot see

This hunt has two primary blind spots. First, it relies on endpoint telemetry. If an infection occurs on a host without an EDR agent, the hunt returns no results for that asset, potentially creating a false sense of security. Second, it cannot see the initial clipboard injection. We only see the activity once the user pastes and runs the command in PowerShell; the act of the website placing the command into the user's clipboard is invisible to these surfaces.

### How to run it

This playbook is an open `hunt.md` file. You can import it into Huntbase or any hunt.md-aware runtime. It uses standard SQL for queries against endpoint telemetry surfaces. Before running, review the `c2_domains` parameter to include any new infrastructure identified in your own environment or recent intelligence reports.
