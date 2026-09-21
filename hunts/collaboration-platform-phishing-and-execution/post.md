# Hunting Collaboration Platform Phishing and Payload Sideloading

### Why now
Adversaries are exploiting the high trust users place in collaboration tools. In the report [Identity Abuse Through Trusted Communication Channels](https://unit42.paloaltonetworks.com/communication-channel-identity-risks/), Unit 42 describes how attackers move away from email to deliver phishing links and malicious payloads via Slack, Teams, and Google Meet. This shift bypasses traditional email-centric security stacks and forces security teams to find new ways to correlate SaaS-based initial access with endpoint behavior. Security practitioners need visibility into these channels because the inherent trust in collaboration platforms often leads to higher click rates and faster execution of malicious files.

### Hypothesis
An intruder has compromised an enterprise identity using collaboration tools to bypass email-based controls and execute malicious code via sideloading or malicious dependencies.

### How the hunt flows
The hunt begins by identifying the attack surface across the fleet. The first query against the software inventory surface lists every host running Slack, Teams, Zoom, or Google Meet. This scoping step ensures the analyst knows which hosts are susceptible to this specific vector and provides a focused list of devices for the more resource-intensive telemetry queries that follow.

The second phase identifies leads through network telemetry. The hunt identifies HTTP requests to known phishing or recruitment-themed domains—such as Google Sites or Slack hooks—that contain authentication keywords like "login," "verify," or "sign-in." Because these domains are often legitimate, the hunt filters for specific patterns observed in recent campaigns rather than blocking the domains outright. An agent then reviews the identified URLs and user agents. The agent distinguishes between legitimate SaaS traffic and potential impersonation or credential harvesting attempts by looking for non-browser user agents or outdated versions of collaboration clients.

If the agent or analyst confirms a suspicious lead, the hunt triggers a parallel investigation phase on the endpoint to find evidence of exploitation. One query searches for rare binaries—those appearing on three or fewer hosts—running from user-writable paths like AppData, Temp, or the Downloads folder. Grouping by filename and path helps filter out common per-user installations while highlighting unique payloads. Simultaneously, another query checks for the loading of masquerading DLLs, such as lpk.dll, from these same locations. This combination targets both the execution of standalone payloads and common sideloading techniques where a legitimate application loads a malicious module.

Finally, an agent correlates the network and endpoint findings into a single verdict. The agent builds a timeline to see if the suspicious communication lead immediately preceded the execution of a rare binary or the loading of a sideloaded module. This correlation is what elevates the activity from a series of minor anomalies to a confirmed compromise.

### Why this is a hunt
This activity is a hunt rather than a simple detection because of the context required to confirm a compromise. A standard detection might alert on the presence of a file named lpk.dll in a user folder, but such a rule often generates false positives from legitimate software or developers. This hunt asks broader questions: did the host also communicate with an authentication-themed phishing link in the same window? Is the parent binary rare across the entire fleet? By using three surfaces—software inventory, HTTP activity, and process/module telemetry—and an agent to weigh the combined context, the hunt identifies high-confidence identity compromises that a standalone rule would miss.

### What the hunt cannot see
This hunt requires visibility into endpoint HTTP activity. If the organization does not collect proxy logs or endpoint-originated network telemetry, the initial phishing lead cannot be established, and the hunt will close early. Furthermore, the hunt cannot access the private content of messages within Slack or Teams. It identifies the destination of the traffic and the binary results on the host, but it cannot see the specific social engineering bait that enticed the user to click. It also misses out-of-band communication that does not involve the monitored collaboration clients.

### How to run it
This hunt is an open hunt.md playbook. You can import it into Huntbase or any environment that supports the hunt.md format. It uses configurable parameters for lookback periods and domain lists to adapt to evolving social engineering campaigns. The modular design allows you to run the scoping step first and then decide whether to proceed with the full investigation based on the presence of collaboration tools in your environment.
