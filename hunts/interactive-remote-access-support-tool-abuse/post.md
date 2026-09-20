# Hunt for UNC3753 Interactive RMM Abuse and VDI Pivots

### Why This Hunt Matters

UNC3753, also known as Luna Moth, bypasses traditional perimeter defenses using "Bazarcall" style vishing. Mandiant detail this campaign in their report, [UNC3753 targeted campaign against US law firms](https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms). These actors do not rely on zero-day exploits or complex malware. Instead, they talk a user into downloading legitimate remote management tools (RMM) like AnyDesk or SuperOps to gain a foothold. This approach is effective because these tools are signed, functional, and often permitted by security policies.

### The Hypothesis

An intruder uses vishing to direct users to a self-destructing note service and installs unauthorized RMM tools to pivot into corporate VDI infrastructure.

### How the Hunt Flows

The hunt begins with a scoping phase using the `hb_software_inventory` surface. This query builds a fleet-wide inventory of hosts running RMM software or VDI clients. The list includes AnyDesk, Bomgar, Zoho Assist, and SuperOps. Because IT teams use many of these tools legitimately, the hunt does not alert on their mere presence. Instead, an agent or analyst evaluates this inventory to find hosts where these packages are unusual or match the specific toolkit observed in UNC3753 campaigns.

Once the hunt identifies candidate hosts, it moves into behavioral analysis across two telemetry surfaces. It queries `hb_dns_activity` for resolutions of `privnote.com`, which the actor uses to transmit instructions that disappear after reading. This provides a marker of the initial social engineering delivery. Simultaneously, the hunt scans `hb_process_activity` for rare command lines. It specifically stacks instances where `curl` or similar utilities download and initiate `msiexec` to install software. This pattern is a high-fidelity indicator when it appears on endpoints that do not typically run ad-hoc installers.

The final phase triages the collected evidence. An analyst looks for a clear temporal sequence: a user resolves a self-destructing note service, then a rare MSI installation occurs, followed by the appearance of RMM or VDI session activity. This correlation is what turns a series of weak signals into a high-confidence intrusion verdict. If the evidence confirms a malicious intrusion, the playbook provides an action to isolate the host and revoke active VDI sessions.

### Known Blind Spots

This hunt has specific blind spots. It relies on endpoint telemetry, which is often missing on personal BYOD devices. If a user initiates the session on a personal laptop to access a corporate VDI, the initial download and RMM install happen outside our view. The hunt also cannot capture the vishing audio itself; we only observe the technical artifacts left behind after the user follows the intruder's verbal instructions.

### How to Run This Hunt

We provide this logic as a `hunt.md` playbook. This format allows you to import the logic into Huntbase or any compatible runtime to execute the queries and manage the triage workflow. This approach is more effective than a static detection because it allows an analyst to weigh the legitimacy of the RMM tools against the rare behavioral markers of the intrusion.
