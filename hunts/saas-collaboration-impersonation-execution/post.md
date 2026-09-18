# Hunting for Impersonation and Execution via SaaS Collaboration Channels

Adversaries are increasingly moving away from email-based phishing, opting instead to exploit the implicit trust found in enterprise collaboration tools like Slack and Microsoft Teams. A recent report from Unit 42, [Identity Abuse Through Trusted Communication Channels](https://unit42.paloaltonetworks.com/communication-channel-identity-risks/), details how campaigns like "Contagious Interview" lure developers and HR staff into running malicious commands or installing rogue certificates. We have published a new hunt design to address these specific patterns where traditional email gateways are blind.

### The Hypothesis
The hunt operates on the hypothesis that an adversary is leveraging impersonation on collaboration platforms to trick users into executing malicious developer commands (such as npm install or git clone) within user-writable paths or installing non-standard root certificates. These actions typically serve as the bridge between a social engineering lure and full endpoint compromise.

### How the Hunt Flows
The hunt begins by identifying hosts with active collaboration software installations to establish a relevant search scope. We specifically look for Slack and Teams presence to narrow the fleet to users most susceptible to these impersonated lures.

Next, the hunt pivots to endpoint process activity, searching for developer tools like npm or git being executed within directories like Downloads or Desktop. Legitimate engineering workflows rarely involve active development in these locations, making them a high-signal indicator for the "Contagious Interview" pattern where victims are asked to review code from a ZIP file.

We then broaden the investigation through a parallel corroboration phase. This step stacks binaries launched from user-writable paths to identify rare payloads (seen on fewer than three hosts) and monitors for common system DLLs being loaded from the Downloads folder— a classic sign of DLL sideloading following archive extraction. Simultaneously, we examine DNS logs for lookups to known-abused hosting infrastructure like Google Sites and various Slack-themed phishing domains.

Finally, the hunt inspects the local certificate store. We specifically target root certificates installed in user stores rather than the system store. The presence of unauthorized CAs is a significant indicator of potential credential harvesting or person-in-the-middle configurations.

### Limitations and Blind Spots
This hunt focuses on the endpoint fallout of a social engineering lure. It cannot see the content of the Slack or Teams messages themselves without native API integration into those platforms. Additionally, the current schema for certificate monitoring may require manual pivoting through the certificate owner's identity to attribute a rogue CA to a specific host, as hostnames are not always directly joined to certificate records in all telemetry sets.

### Running This Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime capable of parsing `hunt.md` files. This format allows you to run the scoped queries, evaluate the results through an automated triage agent, and initiate isolation or review tasks based on the findings. Because this behavior often involves legitimate tools in illegitimate contexts, the agent-led triage is critical for distinguishing between a developer's messy workspace and an active intrusion.
