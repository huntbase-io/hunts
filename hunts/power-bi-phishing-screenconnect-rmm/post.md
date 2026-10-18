# Hunting Power BI Phishing and Rogue ScreenConnect RMM

### Identifying the Power BI Phishing Chain

Recent research from Huntress titled "Phishing Campaign Abuses Microsoft Power BI to Deploy Rogue RMMs" (https://www.huntress.com/blog/screenconnect-power-bi) highlights a campaign where attackers bypass email security by hosting lures on trusted Microsoft infrastructure. The adversary uses legitimate Power BI dashboard links to redirect victims to external staging domains. These domains then serve rogue ScreenConnect installers to the victim. We published this hunt to help teams find these specific delivery steps before the attacker gains full control.

### The Hypothesis

The adversary uses legitimate Microsoft Power BI dashboard views to host phishing lures that redirect users to malicious staging domains. These redirects result in the download and installation of rogue Remote Monitoring and Management (RMM) tools like ScreenConnect. By starting the attack on a trusted domain like app.powerbi.com, the adversary successfully avoids many standard email reputation filters.

### How the Hunt Flows

The hunt begins with the HTTP surface. The first query scopes the environment for any hosts visiting the Power BI view path or the known staging domains like dailylifeproject.site. Because the Power BI link is legitimate, we filter for specific path structures identified in the source research to reduce noise. This step provides a list of potentially compromised hosts that interacted with the lure.

Once we have a list of candidate hosts, the hunt runs two corroboration queries in parallel. One query monitors the file activity surface for writes of the ScreenConnect installer. It looks for the default client setup filename and a specific file hash in user-writable paths. The second query examines the DNS surface to stack-rank ScreenConnect relay subdomains across the fleet. We look for "rare" relays—instances seen on only a few hosts—which helps distinguish a rogue attacker-controlled tenant from a standard corporate deployment used by your IT department.

In the final phase, an analyst or automated agent triages the findings. A host that visited a staging domain and subsequently downloaded the RMM installer or connected to a rare relay receives a malicious verdict. This correlation allows us to move beyond simple detection and understand the context of the RMM usage. If the verdict is malicious, the hunt triggers an isolation action to prevent the adversary from executing further commands through the rogue RMM.

### Blind Spots and Limitations

This hunt relies heavily on web and DNS telemetry. If your environment lacks HTTP activity logs or proxy data, you cannot see the initial redirect from Power BI to the staging domain. The hunt then depends entirely on finding the ScreenConnect file write or the DNS relay connection. Additionally, if the host uses DNS-over-HTTPS (DoH) to resolve staging domains or ScreenConnect relays, standard endpoint DNS monitoring will miss that traffic. In those cases, you must rely on process and file monitoring to catch the RMM installation after the fact.

### How to Run This Hunt

This hunt is available as an open hunt.md playbook. You can import this file directly into Huntbase or any hunt.md-compatible runtime to begin your investigation. The playbook includes the specific staging domains and hashes identified in the Huntress research. If you find a confirmed rogue instance, follow the handoff steps to investigate multi-stage PowerShell scripts often deployed by this adversary after the initial RMM access.
