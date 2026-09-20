# Hunting SharePoint Unauthenticated Remote Code Execution Chains

### Why now
Rapid7 recently published details on CVE-2026-63520 (https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed/), a critical remote code execution vulnerability in Microsoft SharePoint. This exploit often chains with CVE-2026-55040 to allow an unauthenticated attacker to take control of the server. Because SharePoint is frequently exposed to the internet, these vulnerabilities represent a high risk of initial access.

### Hypothesis
An attacker exploits the CVE-2026-55040 and CVE-2026-63520 chain to bypass authentication and execute arbitrary commands via the SharePoint worker process on unpatched servers.

### How the hunt flows
The hunt starts by scoping the environment. The first query inspects the software inventory to find every host running Microsoft SharePoint. This step identifies the specific fleet at risk and allows the analyst to narrow the search, reducing noise from unrelated web servers or workstations.

Next, the hunt analyzes web traffic on the identified servers. It focuses on HTTP requests reaching Business Connectivity Services or the `_vti_bin` directory. The query performs a stack-count on URI paths and status codes. It filters for rare paths seen on fewer than three hosts. This highlights anomalous targeting that deviates from normal administrative or user traffic.

The third phase pivots to host-level process telemetry. It searches for shell interpreters like `cmd.exe` or `powershell.exe` where the parent process is `w3wp.exe` (the IIS worker process). On a SharePoint server, the worker process should rarely spawn interactive shells. This behavior strongly suggests that an attacker successfully triggered code execution via a web request.

Finally, an analyst correlates these results. They compare the timing of rare URI requests with the appearance of suspicious child processes. This correlation confirms if the web traffic caused the execution, providing a clear verdict on whether the host is compromised.

### Blind spots
This hunt has two primary limitations. First, it relies on the availability of HTTP activity logs. If a SharePoint server does not log web requests to the central telemetry store, an exploit attempt might only leave process execution evidence. Second, the hunt cannot inspect the encrypted payload within HTTPS requests. It identifies the target URI and the resulting behavior, but it cannot see the serialized .NET gadget chain that triggers the vulnerability.

### How to run it
We provide this hunt as an open `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any compatible runtime. You can run the queries sequentially to identify your SharePoint footprint, baseline your web traffic, and audit process behavior. Because it uses correlation across three different telemetry surfaces, this hunt provides higher confidence than a standalone process detection rule.

Rapid7 — CVE-2026-63520 Microsoft SharePoint Remote Code Execution
