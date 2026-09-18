# Hunting Automated Identity Persistence via Adversary VPS Infrastructure

A recent report from Huntress, "An attacker blunder gave us a look into their operations" (https://www.huntress.com/blog/rare-look-inside-attacker-operation), provided a rare view into how modern adversaries manage large volumes of stolen credentials. The research highlights the use of automated workflows involving platforms like Make.com and Telegram, often originating from Virtual Private Server (VPS) infrastructure. This hunt is designed to find these persistent access patterns within your own environment.

### The Hypothesis
An adversary is maintaining persistent access to a large volume of compromised identities using automated workflows originating from VPS infrastructure. This activity is visible as high-density account access—where a single external IP successfully authenticates to multiple unique accounts—accompanied by internal host communications to those same IPs or automation-related domains.

### How the Hunt Flows
The hunt begins by identifying lead indicators in identity logs. We look for external source IPs that have successfully signed into a number of unique accounts exceeding a specific threshold. This step focuses on successful logins rather than failures to bypass traditional brute-force detections. We specifically prioritize IPs belonging to VPS providers like Virtuo, which are commonly used for attacker infrastructure.

Once suspicious IPs are identified, the hunt pivots to network telemetry. We search for internal hosts that have established outbound connections to these same external IPs. This helps identify if an internal machine is being used as a "jump box" or an automation node by the adversary to maintain their foothold.

To further corroborate the use of automated adversary workflows, we examine DNS activity from the flagged internal hosts. We look for resolutions of domains associated with the automation tools mentioned in the source research, such as Make.com and the Telegram API. Seeing these lookups from a host already tied to high-density authentication provides high confidence in malicious persistence.

Finally, the hunt synthesizes these findings. An analyst or automated agent weighs the account density against the network and DNS evidence to provide a final verdict. This allows for a targeted response, such as isolating suspected jump boxes and revoking compromised session tokens.

### Blind Spots
This hunt relies on centralized identity logs. If an adversary is using identities on SaaS or cloud providers that are not currently reporting to your central security platform, that activity will remain invisible. Furthermore, if the adversary is managing credentials exclusively from unmanaged devices that lack an EDR agent, we will see the sign-in density but will lose the ability to correlate that activity to a specific internal network pivot.

### How to Run This Hunt
This hunt is packaged as a `hunt.md` playbook. It is designed to be imported into Huntbase or any other `hunt.md`-aware runtime. The playbook utilizes parameterization, allowing you to adjust the unique-user threshold based on your organization's baseline of legitimate corporate proxies or shared infrastructure. Because it spans identity, network, and DNS surfaces, it provides a level of context that single-surface detection rules cannot achieve.
