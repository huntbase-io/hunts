# Hunting Identity Attacks from Clean Hosting Infrastructure

### Why This Hunt Matters

Adversaries rent space on legitimate platforms like Railway and 1337 Services GmbH to host their attack infrastructure. In the article Adversary Infrastructure: Herd Immunity for Microsoft 365 (https://www.huntress.com/blog/itdr-adversary-infrastructure), Huntress explains how these clean IP ranges bypass automated risk scoring in Entra ID. Because these IPs belong to trusted developer services, they often carry a high reputation that evades standard blocklists. This hunt identifies that activity by looking for successful authentications that originate from these specific hosting clusters before the adversary can fully exploit a stolen session.

### The Hypothesis

An adversary uses trusted developer or cloud hosting platforms to bypass identity risk scoring, using legacy protocols (ROPC) or Device Code Flow to steal or replay session tokens.

### How the Hunt Flows

The hunt begins by querying the hb_auth_signin surface for successful logins originating from known malicious IP ranges. This scoping step provides the initial leads of which accounts and hosts might be compromised. The hunt filters for specific IP prefixes associated with documented hosting abuse to ensure the initial data set remains manageable for further enrichment.

Following the initial leads, the hunt moves into a parallel evidence-gathering phase. The first branch stacks authentication protocols to find rare IP addresses. The hunt targets IPs using ROPC or Device Code Flow against a small number of users. This helps an analyst distinguish between high-volume legitimate services and targeted adversary activity like password spraying or token theft. Many adversaries prefer these protocols because they often bypass modern MFA requirements or allow for easier automation.

Simultaneously, the second branch queries the hb_network_connection surface to find endpoint processes communicating with the same malicious IP ranges. The hunt uses the scope_hosts parameter to focus this search on the machines identified in the scoping phase. This step confirms whether a local process on a user's machine is actively interacting with the infrastructure used for the sign-in, which often points to an AiTM relay or a reverse proxy.

Finally, an analyst synthesizes these data points—successful logins, legacy protocol usage, and host-side network traffic—to reach a verdict. If the activity appears malicious, the analyst proceeds to revoke active sessions and force password resets. The hunt then directs the analyst to review hb_cloud_api_activity for signs of persistence, such as new inbox rules or updated MFA devices.

### Blind Spots

This hunt requires Entra ID P1 or P2 licensing to ensure sign-in logs are available in the hb_auth_signin surface. If logging is disabled, the hunt will not see the initial access. Additionally, the adversary may rotate to new hosting infrastructure not yet included in the malicious_ranges parameter. Because the hunt relies on known IP clusters, it will miss attackers who use smaller, less documented hosting providers or compromised residential IPs.

### How to Run This Hunt

This hunt is a published hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your environment. The design uses a gated flow: it only triggers the more expensive protocol stacking and network queries if the scoping step confirms successful sign-ins from the target infrastructure.
