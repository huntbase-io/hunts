# Hunting Automated Ransomware on Vulnerable Endpoints

### Why this hunt matters

Small and medium-sized businesses often face a widening gap between limited security resources and the increasing speed of automated threats. As highlighted in the ESET article, [The quest for simplicity: Why SMBs want advanced protection without the complexity](https://www.welivesecurity.com/en/business-security/quest-simplicity-why-smbs-want-advanced-protection-without-complexity/), practitioners need workflows that handle complex attack chains without requiring an army of analysts. This hunt addresses the reality of high-speed ransomware by looking for the transition from a vulnerable state to active data destruction.

### The hypothesis

An automated adversary exploits high-severity vulnerabilities or weak credentials to gain initial access, subsequently executing rare processes from writable paths to encrypt files for extortion.

### How the hunt flows

The hunt begins by narrowing the environment down to the most likely targets. The first query identifies hosts with unpatched, high-severity vulnerabilities. This scoping step ensures that subsequent, more intensive telemetry searches focus on the assets most at risk of exploitation.

The second phase looks for signs of entry in parallel. We search for clusters of web server errors (403 and 500) that target configuration files or scripts, which indicates automated probing. Simultaneously, the hunt checks for excessive authentication failures that suggest a credential stuffing or brute force attempt. An agent then correlates these findings to prioritize hosts that are both vulnerable and showing signs of active interest from an adversary.

Once a potential beachhead is identified, the hunt pivots to execution and impact. We search for rare processes running from user-writable directories like AppData or Public. At the same time, we monitor for bursts of file modifications exceeding 1,000 touches per hour. This combination of rare execution and high-speed file activity differentiates ransomware from typical administrative tasks or backup processes.

Finally, the analyst triages the results. If a host shows the full chain—vulnerability, access anomaly, and mass file impact—the hunt provides an automated action to isolate the host and stop further encryption.

### What this hunt cannot see

This hunt relies on endpoint telemetry and process-level monitoring. It cannot see activity on unmanaged servers or IoT devices where an agent is not installed. If an attack starts on one of these invisible assets and moves laterally via encrypted channels, this hunt will only pick up the trail once the adversary reaches a managed endpoint. Additionally, we do not inspect network traffic for data exfiltration; if the adversary steals data over HTTPS to a common cloud provider before encrypting, that egress remains a blind spot.

### Why this is a hunt, not a detection

A single detection rule for mass file modification often triggers on legitimate software, leading to alert fatigue. This hunt is a playbook because it requires the context of three distinct attack phases. We only reach a high-confidence verdict by correlating the vulnerable state, the initial access evidence, and the rare process execution. This multi-surface approach reduces noise and ensures that response actions, like host isolation, are based on a confirmed attack chain.

### How to run it

This hunt is provided as an open `hunt.md` playbook. It imports directly into Huntbase or any other `hunt.md`-aware runtime. Users can adjust the `lookback_days` and `critical_severity_id` parameters to fit their specific risk profile and historical data retention.
