# Hunting TA488 OWA Exploitation and the OWAReaper Implant

### Why this hunt

Proofpoint recently detailed TA488's use of a 'half-click' XSS exploit to deploy the OWAReaper implant in their report, [Cleaning Out Inboxes: TA488 Comes to Outlook with Another Half-Click Exploit](https://www.proofpoint.com/us/blog/threat-insight/cleaning-out-inboxes-ta488-comes-outlook-another-half-click-exploit). The actor uses an XSS vulnerability to inject a persistent implant into OWA. Because the implant resides in the browser's storage and communicates via legitimate services like GitHub and common image CDNs, standard perimeter blocks rarely catch it. This persistence survives credential resets and device re-imaging, making it a critical threat to long-term mailbox confidentiality.

### The Hypothesis

An intruder exploits CVE-2026-42897 in Outlook Web Access to deploy the OWAReaper implant. The adversary uses anomalous sign-ins to gain access, extracts session data, and conducts exfiltration through GitHub and image CDNs. The infection results in server-side persistence where the actor maintains access to the mailbox even after a user logs out.

### How the hunt flows

The hunt begins by identifying the attack surface. The first query scopes the environment for Exchange servers with unresolved vulnerability findings for CVE-2026-42897. This narrows the investigation to infrastructure susceptible to the half-click XSS trigger.

The second phase focuses on authentication and session interaction. The analyst baselines OWA sign-in events to find rare source IPs or unusual login frequencies. Simultaneously, the hunt monitors for requests to sessiondata.ashx, a specific handler OWAReaper uses to steal user identity and configuration details. This phase aims to identify potential beachheads where an account was already compromised to deliver the exploit.

The third phase investigates network operations typical of the implant. The hunt looks for automated polling of the GitHub Search API, which the actor uses for command and control. It also scans for high-fidelity indicators of exfiltration: requests to acocdn.com or legitimate image CDNs like weserv.nl and slack-imgs.com that carry encrypted URI paths or specific filenames like msanalytics.json.

A final triage step brings these surfaces together. An analyst evaluates whether the hosts identified in the scoping phase correlate with the anomalous logins and the specific C2 network patterns. This behavioral approach identifies the full infection chain rather than relying on a single static indicator.

### What the hunt cannot see

This hunt relies on network and authentication telemetry. It cannot see the implant's code inside the browser's localStorage or IndexedDB without direct endpoint forensics. Furthermore, if the initial exploit email is unavailable, the analyst cannot confirm the exact HTML trigger or lure used to initiate the XSS. The hunt identifies the presence of the implant through its network behavior, not by analyzing the browser's memory.

### How to run it

This hunt is available as an open hunt.md playbook. Analysts can import it directly into Huntbase or any hunt.md-aware runtime. Because it pivots from infrastructure vulnerabilities to specific web service abuse, it works best in environments with central HTTP and authentication logging. The playbook includes automated triage steps to help an analyst quickly confirm the severity of a match before moving to host isolation.
