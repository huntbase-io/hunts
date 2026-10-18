# Hunting Iron Man System Phishing and Interactive Exfiltration

### Why now

Microsoft's recent report, [The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/), exposes how adversaries like Storm-2990 and Storm-3119 use the Iron Man System phishing kit. These actors do not just steal static credentials; they use interactive proxying to bypass MFA in real-time. This hunt identifies those active harvesting sessions by looking for the specific infrastructure and behavioral markers left behind on the endpoint.

### The Hypothesis

An adversary is operating the Iron Man System phishing kit to harvest credentials in real-time. They use specific domains like `jewishchoice.org` for infrastructure management and depend on the Telegram Bot API for automated exfiltration of stolen secrets. This interaction requires a persistent or high-frequency connection between the victim's browser and the attacker's infrastructure, often mimicking WebSocket behavior.

### How the Hunt Flows

The hunt first identifies hosts running business productivity software, such as SharePoint, OneDrive, and Google Drive. These applications represent the primary targets for the Storm-2990 ecosystem. Narrowing the scope to these hosts ensures the hunt focuses on high-value beachheads where credential harvesting is most likely to occur.

Once scoped, the hunt launches three parallel queries to gather evidence. The first query checks DNS logs for resolutions of known management infrastructure, including `jewishchoice.org`. Any hit here indicates the host is interacting directly with the attacker's command-and-control surface.

The second query looks for behavioral heuristics in network traffic. It identifies hosts with sustained, high-packet outbound traffic on port 443. Because Iron Man System relies on real-time operator-victim interaction, these sessions often exhibit high packet counts characteristic of WebSockets used for interactive harvesting.

The third query searches for direct connections to the Telegram Bot API. The kit uses this channel to send real-time notifications to the operator when a victim enters credentials. Finding requests to `api.telegram.org/bot` on a host that also shows the previous network heuristics confirms the exfiltration phase.

A final triage step synthesizes these signals. An analyst or agent examines the converged evidence to distinguish legitimate application traffic from an active phishing session. If the hunt finds concurrent DNS hits and Telegram exfiltration, it triggers immediate host isolation.

### What the Hunt Cannot See

This hunt relies heavily on network and HTTP telemetry. If the adversary uses a non-HTTP method or the MTProto protocol for Telegram communication, it will not appear in the HTTP activity logs. Furthermore, identifying WebSockets specifically requires TLS decryption at the network proxy; without it, the hunt must rely on packet-volume heuristics which may catch other high-traffic applications.

### How to Run it

This hunt is a `hunt.md` playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your estate. If you lack automated orchestration, you can run the individual SQL queries against your EDR or SIEM to manually verify the presence of Iron Man System infrastructure.
