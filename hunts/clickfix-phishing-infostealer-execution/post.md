# Hunting ClickFix Social Engineering and Infostealer Execution

### Why now

Adversaries increasingly use social engineering to bypass modern endpoint defenses. ClickFix is a primary example, accounting for over 50 percent of malware loader activity in 2025. Huntress recently detailed the operational impact of these interventions in Defense Drill Interventions (https://www.huntress.com/blog/defense-drill-interventions). This hunt targets the specific moment a user manually executes a command from a malicious landing page.

### The Hypothesis

An adversary tricks a user into manually executing an encoded command from a ClickFix landing page. The user believes they fix a browser error, but the command actually downloads and executes an infostealer. This infostealer then targets browser credential stores to harvest sensitive logins and session cookies for further exploitation.

### How the Hunt Flows

The hunt begins by searching hb_process_activity for terminal shells like PowerShell or CMD. The first query identifies instances where these shells appear as children of common web browsers such as Chrome, Edge, or Firefox. It isolates command lines containing indicators of manual execution or obfuscation, such as -enc, iex, or -command.

Next, the playbook uses an agent to evaluate the identified command lines. This automated analysis looks for Base64 encoded blobs and patterns associated with infostealer loaders. By analyzing the intent of the command, the agent filters out legitimate browser-driven tasks and background software updates that often cause noise in static detection rules.

Once the agent flags a suspicious lead, the hunt initiates a fan-out investigation. The first parallel query calculates the rarity of the command line across the entire fleet. Malicious social engineering commands typically appear on a single victim or a small cluster, whereas legitimate management scripts appear on many hosts. This prevalence check provides a high-confidence signal of manual tampering.

Simultaneously, the hunt monitors hb_file_activity for unauthorized access to browser profile data. It looks for non-browser processes reading the Login Data files where credentials are stored. Finding a rare, browser-spawned shell followed by unauthorized file access to the credential store creates a high-fidelity case for a successful infection.

An analyst then triages the synthesized evidence. They confirm if the host was compromised by correlating the rare execution with the subsequent harvesting behavior. If the infection is verified, the playbook includes steps for immediate host isolation and session revocation to prevent further theft.

### What the Hunt Cannot See

This hunt has two primary blind spots. It relies on accurate parent-process telemetry. If an adversary uses advanced techniques to spoof the parent process or otherwise decouple the shell from the browser, the lead query does not capture the execution. Additionally, the hunt requires visibility into file-open events. If the environment only logs file modifications or deletions, the stealthy read operations performed by infostealers will be invisible to the analysis.

### How to Run it

This hunt is a hunt.md playbook. This format allows for portable, structured hunting that imports into Huntbase or any compatible runtime. To run it, adjust the browser_binaries and shell_binaries parameters to match your specific environment. We recommend a default 14-day lookback period to capture recent social engineering attempts while maintaining query performance.
