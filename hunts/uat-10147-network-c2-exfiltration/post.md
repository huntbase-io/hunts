# Hunting for UAT-10147 Network C2 and Data Exfiltration Patterns

### The Shift to Automated Operations

A recent report from Cisco Talos, [UAT-10147 integrates agentic AI into post-compromise operations](https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/), details a Chinese-speaking adversary using AI playbooks to scale their activities. While the use of AI for task automation is a significant evolution, the underlying network tradecraft remains observable. This hunt focuses on identifying the infrastructure and exfiltration patterns used by this group once they have established a foothold on web-facing assets.

### The Hypothesis

We hypothesize that an adversary is using typo-squatted system processes (specifically `svchosts.exe`) and common command-line transfer tools to exfiltrate system telemetry and maintain command-and-control (C2) with external Nacos or QuasarRAT infrastructure. By monitoring the outbound behavior of these tools rather than just static IP addresses, we can identify compromised assets even when the attacker rotates their infrastructure.

### How the Hunt Flows

The hunt begins with a scoping phase on the `hb_software_inventory` surface. UAT-10147 specifically targets internet-exposed software like Zimbra, AjaxPro, and Telerik. We narrow our search to hosts running IIS, Nginx, or Apache to prioritize high-risk ingress points where post-exploitation scripts are most likely to be deployed.

Once the scope is established, we move into a parallel analysis phase across network and DNS surfaces. The first pivot looks for outbound network connections from a process named `svchosts.exe` (note the extra 's'). This is a known QuasarRAT variant used by this actor to mimic the legitimate Windows `svchost.exe`. Any outbound activity from a process with this specific name is considered a high-confidence indicator of persistence.

Simultaneously, we analyze the `hb_network_connection` surface to identify rare exfiltration sinks. The adversary uses `curl` and `certutil` to send system identity data to external Nacos configuration servers. We stack-count the external destinations contacted by these tools and filter for those appearing on fewer than three hosts. This helps distinguish legitimate administrative updates from targeted data exfiltration to attacker-controlled endpoints.

Finally, we check the `hb_dns_activity` surface for known C2 indicators provided in the Talos report. This acts as a secondary verification for the behavioral signals. If a host shows both a typo-squatted process and a connection to a rare destination or known domain, it is flagged for immediate isolation.

### What This Hunt Cannot See

There are two primary blind spots to consider. First, if the malware runs as a specialized system service or uses raw sockets that bypass EDR process-to-network mappings, we may lose visibility into the `svchosts.exe` outbound activity. Second, without TLS inspection or forward proxy logs, we cannot see the content of the HTTP POST bodies sent via `curl`. We can identify that data was sent to a rare destination, but we cannot confirm it contained system telemetry without further forensic analysis.

### Why This Is a Hunt, Not a Detection

A simple detection rule for the `adminapi.tippusoni.in` domain is easily bypassed by the adversary changing their configuration. This is a hunt because it uses prevalence-based baselining of common administrative tools and focuses on the subtle behavioral mismatch of a typo-squatted process name. It requires an analyst to evaluate the context of the outbound traffic to differentiate between an IT admin's script and an AI-driven exfiltration playbook.

### How to Run It

This hunt is packaged as an open `hunt.md` playbook. It can be imported directly into Huntbase or any other `hunt.md`-aware runtime. The playbook allows you to adjust the lookback period and provide your own list of C2 indicators for correlation.
