# Hunting for ClickFix Shell Execution and Cookie Theft on macOS

### Why Now
Attackers increasingly target macOS users with sophisticated social engineering lures that bypass multi-factor authentication. A recent report by Huntress, [ClickFix to BEC in 24 Hours: Tragic Quadrant](https://www.huntress.com/blog/clickfix-bec-tragic-quadrant-doris), describes a workflow where users are directed to run a terminal command to "fix" a browser error. This command exfiltrates browser cookies, leading to a full account takeover in less than a day. This hunt provides a structured way to find these indicators in your environment.

### The Hypothesis
An intruder uses a social engineering lure to trick a macOS user into executing a malicious shell command in Terminal. This command uses standard system binaries to extract and exfiltrate browser session cookies, enabling the attacker to hijack the user's active session and access cloud resources without needing a password or MFA token.

### How the Hunt Flows
The first phase scopes the environment for suspicious shell activity. A query scans process telemetry for shell interpreters like sh, bash, or zsh that execute commands containing both curl and base64. This specific combination is a hallmark of ClickFix payloads, which often use encoding to hide C2 URLs or data exfiltration logic. This step generates a list of suspect hosts for further investigation.

Once the hunt identifies suspect hosts, it runs two parallel checks to corroborate the threat. The first check baselines the command lines across the environment. It looks for rare shell payloads that appear on only a few hosts, separating one-off attacks from legitimate administrative scripts. This helps narrow the focus to truly anomalous activity.

The second parallel check monitors file activity for unauthorized access to browser cookie databases. The query looks for shell processes or curl reading files in paths associated with Google Chrome, Microsoft Edge, and Safari cookie storage. Under normal conditions, only the browser processes access these files. Seeing a terminal shell read these paths suggests active credential or session theft.

In the final phase, an analyst or automated agent triages the results. The hunt requires that the suspicious file access occurs shortly after the shell execution. If the temporal context and the rarity of the command align, the host moves to containment to revoke active sessions and isolate the device.

### What This Hunt Cannot See
This hunt relies on full command-line arguments. If your telemetry provider truncates long commands or misses specific arguments, the initial scoping query may not distinguish ClickFix patterns from normal shell usage. Additionally, if an attacker uses memory-mapping techniques to read cookie files without triggering standard file-read events, the exfiltration might not appear in the file activity logs.

### How to Run It
This hunt is available as an open-source hunt.md playbook. You can import it into Huntbase or any security platform that supports the hunt.md format. Because it correlates process rarity with file access, it functions as a hunt rather than a static detection, helping you find successful session theft that lacks a traditional malware signature.
