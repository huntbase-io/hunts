# AI-Impersonation Attack and Stealer Execution Hunt

### Why Now
Threat actors are moving beyond traditional SEO poisoning to exploit the trust users place in AI platforms. A recent report by Huntress, [The AI Attack Surface: How Threat Actors Abuse Trusted AI Platforms](https://www.huntress.com/blog/ai-attack-surface), describes "ClickFix" campaigns where attackers use shared AI conversations to deliver malicious instructions. These lures masquerade as technical support, convincing users to copy and execute terminal commands that deploy credential stealers like AMOS or MacSync.

### The Hypothesis
An intruder uses a trusted AI platform to trick a user into executing a terminal command from the clipboard, establishing persistence and stealing credentials. The attacker relies on the user's perception that content within a ChatGPT or Claude session is safe, bypassing the scrutiny typically applied to search engine results.

### How the Hunt Flows
The hunt starts by identifying interaction with known redirect infrastructure. A scoping query scans DNS activity for resolutions of malicious domains observed in AI-lure campaigns. This initial step is a cost-effective filter, narrowing the scope to hosts that likely interacted with a fraudulent AI artifact.

An analyst evaluates these DNS leads to determine if the timing and process context match the AI impersonation pattern. If the lead is suspicious, the hunt opens three parallel forensic paths. The first path examines process activity for shell interpreters—such as bash, zsh, or PowerShell—executing commands that pipe network downloads directly into a shell or use encoded arguments.

The second path identifies persistence by baselining scheduled jobs across the environment. It flags tasks that are unique to the suspicious hosts, as stealers often create local persistence to maintain access after the initial terminal execution. This helps separate one-off administrative tasks from malware-driven automation.

The third path monitors access to sensitive files. The query looks for processes reading SSH keys, AWS credentials, or browser keychains. This provides evidence of the final stage of the attack: the exfiltration of high-value secrets. Finally, an analyst correlates these results into a unified verdict, identifying the full lifecycle from the initial redirect to data theft.

### What the Hunt Cannot See
This hunt has specific blind spots. It cannot see the exact text the user copied from the AI platform because standard endpoint telemetry does not capture clipboard contents. The analyst sees the execution but not the specific lure that prompted it. Additionally, if the host uses DNS over HTTPS (DoH) or other encrypted DNS protocols that bypass the local resolver, the initial lead query may fail. The hunt also requires comprehensive agent coverage; an unmanaged host interacting with the redirect domain remains invisible to the subsequent forensic queries.

### How to Run It
This hunt is provided as an open `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any runtime that supports the `hunt.md` standard. The playbook includes the specific logic for the gated flow, ensuring you only run expensive forensic queries on hosts that show initial signs of compromise. You can adjust the redirect domain list and the lookback period to fit your environment's specific risk profile.
