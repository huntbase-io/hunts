# Hunting IT Support Impersonation via Microsoft Teams and RMM Tools

### Why this hunt?
In a recent report, [Impersonating IT support: how threat actors turn a remote session into enterprise-wide access](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/), Microsoft Threat Intelligence describes a shift in social engineering. Instead of email, adversaries use Microsoft Teams to contact users directly. They masquerade as internal helpdesk or security personnel to convince employees to launch Remote Monitoring and Management (RMM) tools. This bypasses many perimeter controls because the user initiates the outbound connection.

### The Hypothesis
An attacker gains interactive access by impersonating IT support via Microsoft Teams. They coax a user into initiating an RMM session that establishes a bridge into the environment. Once connected, the attacker uses administrative shells to explore the network before deploying persistent implants.

### How the Hunt Flows
The first phase focuses on scoping through external collaboration logs. The query identifies successful sign-ins to Microsoft Teams from external domains. While many organizations allow guest access, the hunt filters for domains that do not belong to known partners. These events provide a list of users and timestamps for the initial contact.

The second phase runs two investigations in parallel. One query stacks RMM tool execution across the entire fleet to find rare software. Attackers often use tools like Quick Assist, AnyDesk, or ScreenConnect that might not be the corporate standard. The second query looks for shells like cmd.exe or PowerShell spawning directly from these RMM processes. A shell under an RMM parent almost always indicates hands-on-keyboard activity by a remote operator.

The final phase uses an automated triage agent to correlate these signals. The agent looks for a specific sequence: an external Teams authentication lead followed by the execution of a rare RMM tool and a shell spawn on the same host within a short window. This correlation reduces the noise of legitimate IT support activity and identifies the specific bridge the attacker is using.

### Blind Spots
This hunt has two primary blind spots. First, if the attacker uses Teams voice calls (vishing) rather than chat, there is no text-based record of the lure. The hunt must then rely on the RMM and shell execution signals alone. Second, the hunt focuses on process execution. If an analyst cannot access network egress logs, they cannot confirm if the RMM tool successfully reached a controller, which might lead to investigating failed connection attempts.

### Running the Hunt
This playbook is available as a hunt.md file. You can import it into Huntbase or any runtime that supports the hunt.md format. It uses SQLite-based queries against your authentication and process telemetry. Before running, configure your internal domains and standard RMM tool list to ensure the baseline correctly identifies anomalies in your specific environment.
