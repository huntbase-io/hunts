# Hunting for Persistence on Linux Network Appliances via Sudo Abuse

Network appliances often sit at the edge of the perimeter with minimal security instrumentation. Recent reporting from Volexity — [VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall](https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/) — highlights how threat actors like UNC5221 exploit this lack of visibility to maintain long-term access. This hunt provides a structured approach to identifying the specific persistence patterns used in these campaigns.

### The Hypothesis
We hypothesize that an adversary has gained initial unprivileged access to a Linux-based appliance and is leveraging misconfigured sudo permissions to write persistence. Specifically, the actor uses the `tee` command with sudo to bypass file permissions and place malicious scripts into system-level cron directories, such as `/etc/cron.d` or `/etc/rc.d`.

### How the Hunt Flows
The hunt begins by scoping the environment. Since these appliances often lack standard EDR agents, we first identify Linux and FreeBSD hosts within the `hb_devices` surface that match known appliance profiles, such as pfSense or Egnyte Storage Sync. This ensures the hunt is focused on the high-risk, low-visibility segments of the infrastructure.

Next, we examine process execution logs in `hb_process_activity`. We are specifically looking for instances where `sudo` is used to execute `tee` with arguments pointing to sensitive configuration directories. While `sudo tee` is a common administrative pattern, its use in conjunction with cron directories by non-standard users is a high-fidelity pivot point for further investigation.

To corroborate these process events, the hunt pivots to `hb_scheduled_job`. We perform a fleet-wide rarity analysis on cron jobs. Attackers often use unique script names or rare paths like `/home/egnyteservice/ssync.sh`. By identifying jobs that appear on only a handful of hosts, we can isolate potentially malicious implants from standard system maintenance tasks.

Finally, we look at `hb_file_activity` to capture the actual file write events. We focus on non-package-manager writes to the crontab and rc.d directories. This step helps identify the specific indicators of compromise mentioned in the source article, such as modifications to Egnyte-specific monitoring scripts.

### What the Hunt Cannot See
This hunt has two primary blind spots. First, without full file-read capabilities on the appliance, we cannot see the actual payload content written by the `tee` command; we only see the metadata of the write. Second, VerdantBamboo is known to remove their persistence files immediately after execution to evade disk scanners. If the telemetry provider does not capture short-lived file events or process execution for the deletion, the window of visibility is limited.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any runtime that supports the open hunt.md standard. Because `sudo tee` can appear in legitimate admin scripts, this is designed as a hunt rather than a static detection, requiring an analyst to review the rare cron entries identified by the final triage step.
