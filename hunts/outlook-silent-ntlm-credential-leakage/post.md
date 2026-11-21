# Hunting Outlook Silent NTLM Credential Leakage (CVE-2026-124194)

### Why now

The Rapid7 — Patch Tuesday - November 2026 report (https://www.rapid7.com/blog/post/em-patch-tuesday-november-2026) describes CVE-2026-124194 as a critical spoofing vulnerability in Microsoft Outlook. This flaw allows an adversary to trigger outbound NTLM authentication by forcing the client to load a crafted file. Because this process happens silently, traditional detection rules often fail to distinguish malicious hash leakage from legitimate network traffic. This hunt provides a structured way to verify if these silent leaks occur in your environment.

### Hypothesis

An attacker is exploiting CVE-2026-124194 by forcing Outlook to initiate outbound SMB connections to an external listener, silently leaking the user's NTLM v2 hash upon opening a crafted file.

### How the hunt flows

The hunt identifies vulnerable Outlook hosts first. The first query pulls data from the hb_vulnerability_finding surface to locate assets where scanners confirmed the presence of CVE-2026-124194. This initial scoping step ensures the analyst focuses on the endpoints where exploitation is technically possible, which reduces the volume of telemetry to be reviewed in subsequent phases.

Next, the hunt baselines legitimate Outlook network destinations. Using the hb_network_connection surface, the query stack-counts all outbound connections from the Outlook process to external IP addresses. By identifying destinations that appear on only a few hosts, the analyst isolates rare or unique IPs that likely represent attacker-controlled infrastructure rather than standard Microsoft or cloud services.

The core of the hunt targets the specific behavioral signature of hash theft. The hunt searches for instances where Outlook initiates a connection on port 445 (SMB) to a non-private external address. Since Outlook has no standard requirement to perform SMB operations over the public internet, any signal here strongly suggests forced NTLM authentication.

Finally, the analyst correlates the findings into a triage verdict. The workflow examines the overlap between the vulnerable hosts identified in the scoping phase and the suspicious SMB egress found later. This correlation allows us to distinguish between systems that are merely unpatched and those where exploitation behavior suggests an active credential theft attempt.

### What the hunt cannot see

This hunt relies on consistent network connection telemetry from the endpoint. If a host lacks EDR coverage or if logging is disabled, an outbound leak will go unrecorded. Furthermore, the vulnerability may attempt to fall back to WebDAV over port 80 or 443 if SMB is blocked. This hunt focuses primarily on port 445; identifying WebDAV-based leaks requires deep packet inspection or proxy logs to differentiate them from normal web traffic.

### How to run it

This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries and analyze your telemetry. Because this is a hunt rather than a static detection, it uses behavioral baselining and environment-wide stacking. This approach helps the security team find novel attacker infrastructure during the critical remediation window following the patch release.
