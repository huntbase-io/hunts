# Hunting for AI-Automated Reconnaissance and Subsequent Identity Abuse

### The Shift in Targeted Fraud

Adversaries are no longer limited by the manual effort required to research targets. ESET Research describes how AI-driven tools now scrape social data and scan for infrastructure vulnerabilities at scale in their article, [AI-driven OSINT in the wrong hands](https://www.welivesecurity.com/en/privacy/ai-powered-osint-why-everyone-viable-target-fraud/). This automation allows even low-skill actors to execute high-fidelity phishing and exploitation campaigns against a broad range of targets.

### The Hypothesis

An adversary is using AI-automated OSINT to identify vulnerable web applications and craft high-fidelity phishing lures, leading to server exploitation and account takeover for fraud.

### How the Hunt Flows

The first phase scopes the environment using vulnerability findings. The query identifies hosts with critical CVEs that AI-assisted reconnaissance prioritizes. By filtering for high-severity issues and known exploited vulnerabilities, we isolate the systems most likely to be targeted by automated scanners.

Simultaneously, the hunt scans for inbound probing and exposed management ports. It looks for high volumes of successful POST requests to web applications and open administrative services like RDP, SSH, or SMB. This step identifies where automated tools have already found a path into the network.

A triage agent determines which hosts face active targeting based on this exposure. This bridges the gap between passive vulnerability data and active scanning evidence, creating a high-confidence list of targets for follow-on investigation.

The next phase hunts for the technical outcomes of a successful breach. One check monitors for web servers spawning shell processes like bash or cmd.exe. This indicates successful exploitation of the vulnerabilities identified earlier, where the attacker has gained command execution on a web-facing host.

Another check identifies anomalous user sign-ins. It flags logins from rare geographic locations or IPs for specific accounts. This suggests successful credential harvesting through personalized phishing, even if no direct malware was involved.

A final assessment agent correlates these signals to confirm a breach. It reconciles host identities and user accounts to map the campaign's full lifecycle from discovery to impact.

### Blind Spots

This hunt relies on EDR and identity telemetry. It cannot see exploitation on shadow-IT or unmanaged servers where the agent is absent. It also lacks visibility into deepfake audio or video used in social engineering, as those interactions occur outside the scope of endpoint logs.

### Running the Hunt

This hunt is provided as an open hunt.md playbook. It imports directly into Huntbase or any hunt.md-aware runtime. Because it correlates vulnerability inventory with active process and identity signals, it provides better context than a single detection rule. Run this to confirm if targeted reconnaissance against your environment has transitioned into a successful compromise.

Source: ESET Research — AI-driven OSINT in the wrong hands
