# Hunting Cloud Identity Masquerading and Obfuscated Command and Control

Cloud security often relies on static permissions, but identities are dynamic. When an adversary compromises a cloud credential, they don't just act; they explore. Recent research from Unit 42, [Unmasking Cloud Identities: From Behavioral Clustering to Automated Detection](https://unit42.paloaltonetworks.com/behavioral-clustering-map-to-cloud-identities/), highlights how behavioral clustering can reveal attackers who hide behind privileged naming conventions and obfuscated infrastructure. Our latest hunt.md playbook implements these findings to help practitioners find functional role masquerading in their own environments.

### The Hypothesis
We hypothesize that an adversary is utilizing over-privileged cloud identities—specifically those masquerading as administrative roles—to perform discovery and enumeration. To evade traditional IP-based detection, the actor is likely routing their management traffic through multi-hop proxies or onion-routing networks, creating a distinct signature across authentication logs, process telemetry, and DNS traffic.

### How the Hunt Flows
The hunt begins with scoping. We use the software inventory surface to identify hosts that possess cloud management tools like the AWS CLI, kubectl, or the Amazon SSM agent. This narrows our focus to the machines most likely to be used for infrastructure management, reducing the noise from general-purpose endpoints.

Once scoped, we pivot to authentication logs. We specifically look for AWS ConsoleLogin events where the username includes strings like 'admin' or 'awsreservedss'. This isn't just about finding admins; it is about finding identities that claim to be admins, which are high-value targets for masquerading. This phase creates our initial list of 'identities of interest'.

Next, the hunt corroborates behavior across three parallel surfaces. We look for the 'how' and 'where' of the activity. We search process logs for specific discovery commands—like listing S3 buckets or IAM roles—and simultaneously baseline source IPs to find logins that are rare across the fleet. We also check DNS activity for requests to Tor or other proxy infrastructure, which provides the network context necessary to distinguish a legitimate admin from a proxied intruder.

Finally, we weigh the evidence. A single 's3 ls' command might be benign, but an 'admin' identity logging in from a rare IP and immediately querying IAM roles while Tor activity is present on the same host represents a critical risk. The hunt concludes by providing an automated triage step to cite these specific rows for analyst review.

### What This Hunt Cannot See
There are two primary blind spots to consider. First, without direct integration into cloud audit logs (like CloudTrail) across every active region, we may miss authentication events occurring in unmonitored or 'dark' regions. Second, if discovery is performed from an unmanaged or 'shadow IT' device that lacks our endpoint agent, we will lose visibility into the process command lines, leaving only the cloud-native authentication signal to work with.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It is designed to be imported directly into Huntbase or any runtime that supports the hunt.md specification. By running this periodically, you can move beyond simple detection alerts and perform a true behavioral audit of your cloud administrative plane. Source: Unit 42 — Unmasking Cloud Identities.
