# Hunting UAT-10147 Persistence and IIS Backdoors

### Why Now

Cisco Talos recently detailed a campaign by a Chinese-speaking adversary, UAT-10147, in their report [UAT-10147 integrates agentic AI into post-compromise operations](https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/). This actor has operationalized one-day exploits at scale, using AI-driven playbooks to automate the post-compromise phase. While their initial access payloads rotate rapidly, their persistence and reconnaissance behaviors remain consistent markers for detection.

### The Hypothesis

We hypothesize that the adversary maintains long-term persistence on web servers by deploying deceptive scheduled tasks (e.g., 'Google Chrome Start') and injecting malicious IIS modules (BadIIS). These backdoors allow the actor to exfiltrate system metadata to cloud sinks while remaining hidden within legitimate server processes.

### How the Hunt Flows

The hunt begins with a scoping phase, identifying hosts in the environment that are currently unpatched against the specific CVEs targeted by UAT-10147, such as CVE-2022-27925 and CVE-2021-3156. This prioritizes assets most likely to have been compromised during the initial exploitation wave.

The persistence phase focuses on deceptive tasks and scripts. We look specifically for the 'Google Chrome Start' task name or batch scripts named 'user.bat' or 'back.bat'. A fleet-wide prevalence pivot is used to identify rare scheduled tasks seen on two or fewer hosts, which often reveals custom persistence scripts mimicking legitimate maintenance tasks.

Integrity checks on IIS instances follow, targeting both reconnaissance and module injection. We look for the use of `appcmd.exe` with XML list site parameters—a prerequisite for the actor's BadIIS module injection. Simultaneously, the hunt identifies DLLs loaded into `w3wp.exe` that are either unsigned or reside in suspicious directories like `C:\Windows\Temp`.

The final behavioral phase monitors network activity from web server worker processes. A key indicator of compromise is `w3wp.exe` initiating outbound TCP connections to external IP addresses. This behavior is inherently anomalous for a process designed to serve inbound requests and strongly suggests a reverse shell or exfiltration channel.

### Blind Spots

This hunt has two primary blind spots. First, without HTTP POST body visibility, we can identify connections to exfiltration sinks but cannot verify the specific metadata stolen. Second, if initial reconnaissance occurred more than 30 days ago, standard process telemetry may have rolled over, leaving only the established persistence mechanisms visible.

### How to Run This Hunt

This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any runtime aware of the hunt.md format. Practitioners should first adjust the `lookback_days` parameter to match their telemetry retention and provide any known-vulnerable hostnames to the `scope_hosts` list to focus the behavioral analysis.
