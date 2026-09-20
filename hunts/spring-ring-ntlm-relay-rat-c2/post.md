# Hunting for Spring Ring NTLM Relay and PowerShell RAT

### Why now
Unit 42 recently published a detailed analysis of the Spring Ring campaign (https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/). These actors use voice phishing (vishing) within Microsoft Teams to trick users into installing malicious software. Once they establish a foothold, they pivot to NTLM relay attacks to move laterally and gain domain-level access. Our team has developed a new hunt.md playbook to help practitioners identify the technical markers of this campaign within their environments.

### The Hypothesis
An attacker has deployed a custom Python environment to facilitate NTLM relay attacks and a PowerShell-based RAT that beacons to external command-and-control infrastructure.

### Finding the custom Python environment
The hunt starts by searching for the deployment of the attacker's tools. The adversary stages a tailored Python interpreter in the ProgramData directory. They use this environment to run scripts like PetitPotam, which triggers NTLM authentication from target servers back to the attacker's infrastructure. The first phase of our hunt identifies any host where this specific binary has executed, capturing the user context and the command-line arguments.

### Corroborating network evidence
Once we identify potential beachhead hosts, the hunt pivots to network-layer evidence. The second phase runs two queries in parallel. One query monitors for outbound SMB scanning on port 445. The adversary uses the custom Python environment to reach out to numerous internal IP addresses, searching for targets for coercion. High volumes of outbound SMB traffic from a single endpoint suggest an active relay attempt.

### Beaconing to command-and-control
The other parallel query focuses on command-and-control activity. The campaign involves a PowerShell-based Remote Access Trojan (RAT) that communicates with specific external domains. We check DNS activity for resolutions of known indicators, such as san-sid.com. This helps confirm if the compromised host has successfully established a link with the attacker's infrastructure.

### Evaluating the intrusion
The triage phase brings these disparate signals together. An analyst reviews the correlated data to determine if the activity represents a true positive. We look for the confluence of the custom execution path, the outbound SMB scanning, and the C2 DNS resolutions. Finding all three on a single host provides high confidence of a Spring Ring intrusion.

### Blind Spots
There are specific limits to what this hunt can see. While we can observe the outbound SMB connections from the beachhead, we lack visibility into the target server's response without server-side logs or Domain Controller events. Therefore, we cannot confirm if the NTLM relay actually succeeded in capturing a valid credential. Additionally, while DNS logs confirm the RAT's intent to communicate, the lack of TLS inspection means the contents of the command-and-control traffic remain hidden.

### How to run it
This hunt is formatted as an open hunt.md playbook. It is designed to be imported into Huntbase or any other hunt.md-aware runtime. This format allows for the seamless transition from initial scoping to multi-surface evidence gathering and final triage.
