# Hunting for Anomalous Cloud Identity Behavior through Behavioral Clustering

### Why Behavioral Clustering Matters
Unit 42 recently detailed how behavioral clustering can map cloud identities and reveal anomalies in their operating patterns in the article Unmasking Cloud Identities: From Behavioral Clustering to Automated Detection (https://unit42.paloaltonetworks.com/behavioral-clustering-map-to-cloud-identities/). Traditional detection rules often rely on static lists of known malicious IPs, which adversaries easily bypass using multi-hop proxies or fresh Tor exit nodes. This hunt adopts the behavioral approach by establishing a baseline of normal administrative access and looking for the outliers that suggest an identity has been highjacked.

### Hypothesis
An adversary has compromised an administrative cloud identity and is accessing the environment through multi-hop proxies or Tor to perform discovery and initial access.

### How the Hunt Flows
The first query scopes privileged authentication events in the hb_auth_signin surface. We target roles matching administrative patterns—such as AWS Reserved SSO or root accounts—that sign in from source IP addresses seen fewer than five times over the last 14 days. This scoping isolates behavioral rarity in sign-in locations to establish leads.

An agent evaluates the risk of these leads by looking for sessions where multi-factor authentication (MFA) was missing. This step gates the hunt. The process only proceeds to network and identity checks if the initial sign-in shows significant risk. If the agent identifies a high-risk lead, the hunt triggers a parallel fan-out phase.

During the fan-out, the hunt searches for evidence across two surfaces. A query on hb_dns_activity finds DNS resolutions to known Tor project domains or .onion addresses from the hosts associated with the suspicious login. Simultaneously, a check on hb_users verifies the identity's security posture for disabled MFA or inactive account statuses that the adversary might use.

A triage agent synthesizes these findings by correlating the rare IP login with any discovered Tor activity or weak identity configurations. If the triage confirms a malicious intersection, the hunt triggers an action to revoke all active cloud sessions for the compromised user.

### What the Hunt Cannot See
This hunt has two primary blind spots. First, it lacks visibility into specific cloud resource discovery operations, such as ListBuckets or ListRoles, because these require normalized cloud audit logs which are not part of the initial endpoint-centric surfaces. Second, the hunt depends on behavioral rarity and DNS queries from managed hosts to detect Tor. If an adversary logs in from an unmanaged device using Tor, and that device does not perform Tor-related DNS lookups through monitored infrastructure, the hunt misses the obfuscation signal.

### How to Run the Hunt
This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any compatible hunt.md runtime to automate the scoping, agent evaluation, and parallel evidence gathering phases. Adjust the admin_patterns parameter to match specific naming conventions for privileged roles.
