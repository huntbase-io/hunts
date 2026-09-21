# Hunting Appliance Persistence and Identity Abuse via Slack

### Why Now
Unit 42 recently detailed a technique in Identity Abuse Through Trusted Communication Channels (https://unit42.paloaltonetworks.com/communication-channel-identity-risks/) where adversaries exploit the trust in collaboration platforms. Instead of targeting users directly, attackers compromise network appliances to manipulate identity controls and exfiltrate data. 

### The Hypothesis
An adversary has modified appliance scheduled tasks to disable MFA and is exfiltrating credentials via native Slack webhook integrations. This approach allows for persistent access and data theft that bypasses traditional endpoint security. 

### Scoping the Appliance
The hunt begins with hb_scheduled_job to find persistence. The scoping query looks for tasks that modify authentication configurations, specifically searching for command lines that contain sed, auth sufficient, or mfa. This identifies appliances where the adversary has already gained high-level access and is attempting to weaken the identity boundary. 

### Correlating Network and Identity Signals
Once the scope is narrowed to suspicious appliances, the hunt moves to hb_http_activity. The adversary uses the native Slack webhook functionality for exfiltration. The hunt identifies POST requests to hooks.slack.com that use script-based user agents like curl or python-requests. These are compared against hb_auth_signin logs to find successful logins where MFA was reported as disabled. This correlation ensures the hunt focuses on malicious activity rather than legitimate IT notifications. 

### Triage and Verdict
An analyst evaluates the combined evidence. A host showing unauthorized task modifications, outbound Slack traffic from a script, and subsequent MFA-less logins for associated accounts receives a malicious verdict. This multi-surface approach is necessary because each signal alone might be benign in a complex environment. 

### Blind Spots
This hunt faces visibility gaps regarding deep OS-level modifications that do not use the scheduled task system. Additionally, while the hunt identifies the exfiltration channel and the tool used, the lack of TLS inspection on outbound HTTPS traffic means the specific credentials or secrets being stolen remain hidden. 

### How to Run
This hunt is an open hunt.md playbook. It imports into Huntbase or any hunt.md-aware runtime. Practitioners can provide a list of appliance hostnames to narrow the scope or run it against the full estate to discover unknown infrastructure risks.
