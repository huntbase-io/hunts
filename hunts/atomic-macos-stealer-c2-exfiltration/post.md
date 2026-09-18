# Hunting Atomic macOS Stealer via Staged HTTP Exfiltration

The Atomic macOS (AMOS) stealer continues to be a persistent threat to macOS users, with recent analysis from Unit 42 (Atomic macOS (AMOS) Stealer Activity: https://unit42.paloaltonetworks.com/atomic-macos-amos-stealer-activity/) highlighting its rapid evolution. AMOS focuses on harvesting sensitive data, such as browser cookies, keychain items, and cryptocurrency wallets. Because the malware’s delivery mechanisms and file hashes rotate frequently, static detection is often insufficient. This hunt focuses on the more durable behavioral signals found during the exfiltration phase.

### The Hypothesis
The hunt is based on the hypothesis that an infected macOS host will exhibit distinctive exfiltration patterns. Specifically, we expect to see sequential HTTP POST requests containing 'stage=' parameters (e.g., stage=boot, stage=wallets) directed toward rare or known-malicious IP addresses. These network signals should correlate with the creation of a temporary staging file, often named 'out.zip', and outbound traffic originating from processes masquerading as legitimate system components.

### How the Hunt Flows
The hunt begins by scoping the environment to identify the active macOS fleet. This step ensures that subsequent, more resource-intensive queries are restricted to the relevant platform, as AMOS is specifically designed for Darwin-based systems.

Once the scope is defined, the hunt executes a parallel investigation across four telemetry surfaces. We search for HTTP POST activity containing specific stage-based URL parameters that indicate data transfer. Simultaneously, we baseline outbound network connections to identify rare process-IP pairs. We specifically exclude known browsers to focus on anomalous traffic from system-sounding processes like accountsd, mdworker, or generic 'helper' binaries that AMOS frequently mimics.

The investigation further corroborates these signals by looking for the 'out.zip' file in the /tmp/ directory. This is where the stealer typically aggregates stolen data before transmission. We also check DNS activity against a list of known AMOS C2 domains to catch infrastructure that has not yet rotated.

In the final phase, the hunt uses an automated triage step to weigh the collected evidence. A high-confidence verdict is reached if a single host demonstrates a 'join' of these signals—for example, the presence of the staging file combined with outbound network traffic from a masqueraded process.

### What the Hunt Cannot See
This hunt has two primary limitations. First, if the malware utilizes HTTPS and the environment lacks SSL/TLS decryption or endpoint-based HTTP dissection, the specific 'stage=' URL parameters will not be visible in network telemetry. In such cases, the hunt relies more heavily on the process masquerading and file staging indicators. Second, the 'out.zip' file is often ephemeral. If the malware completes its exfiltration and deletes the staging file between polling intervals, this local artifact may be missed.

### How to Run it
This hunt is packaged as an open hunt.md playbook. It can be imported directly into Huntbase or any other hunt.md-aware runtime. Because it utilizes behavioral baselining rather than just static indicators, it is designed to be run periodically to catch new infrastructure as it emerges.
