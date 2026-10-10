# Hunting Metasploit RCE Exploits and AArch64 Payload Delivery

### Why This Hunt Matters

In the latest [Metasploit Wrap Up](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-a-collection-of-what-can-only-be-called-eclectic-modules), the community introduced modules targeting unauthenticated remote code execution (RCE) in emerging stacks. These include AI infrastructure like Langflow and LiteLLM, alongside media services like dizqueTV. These modules often deliver AArch64-specific payloads to Windows systems, reflecting a shift in adversary targeting toward ARM-based architecture. Because these services often reside in developer environments or shadow IT, they may lack standard security hardening.

### The Hypothesis

An adversary exploits unauthenticated RCE vulnerabilities in LLM or IPTV web services to run fetch utilities that download AArch64-specific payloads onto Windows systems.

### How the Hunt Flows

The first phase identifies the attack surface. The hunt queries vulnerability findings for specific CVEs, such as CVE-2026-0770, or hostnames associated with Langflow and dizqueTV. This scoping step ensures the subsequent behavioral analysis focuses on hosts that actually run the vulnerable software, reducing noise and query costs.

Next, the hunt executes a parallel analysis of network and process telemetry. It searches HTTP activity logs for URI patterns that match known exploit paths, such as requests to `/validate` or strings containing `ffmpeg`. Simultaneously, it baselines Windows fetch utilities including `ftp.exe`, `tftp.exe`, and `certutil.exe`. The query specifically looks for command lines that appear on five or fewer hosts across the fleet, as these rare commands often represent the adversary's first attempt to pull a second-stage payload.

Finally, an agent correlates these three data points: the presence of a vulnerability, the presence of exploit-related HTTP traffic, and the execution of rare fetch commands. If a host meets all three criteria, the hunt marks it for isolation. The playbook then guides an analyst through a manual review of the retrieved files and the source IPs to confirm the intrusion.

### Blind Spots

This hunt cannot see inside HTTP POST bodies. Many modern exploits, including those targeting LLM exec functions, pass malicious parameters within JSON payloads. If the exploit does not leave a trace in the URI or query string, the network phase will miss it. Additionally, most endpoint telemetry does not explicitly flag the CPU architecture of the host. While the hunt finds the behavior on any Windows system, it cannot confirm the host is an AArch64 machine without external inventory data.

### How to Run It

This hunt is available as an open `hunt.md` playbook. You can import it into Huntbase or any hunt.md-aware runtime. Because it uses a baseline of process frequency, we recommend running it over a 14-day window to distinguish between persistent administrative scripts and one-time exploit events.
