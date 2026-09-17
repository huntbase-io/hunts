# Identifying Klue Supply Chain Compromise via Salesforce OAuth Abuse

The recent analysis by Datadog Security Labs, [Detecting the Klue supply chain attack in Salesforce](https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/), detailed how a vendor compromise can lead to persistent unauthorized access via OAuth tokens. When a third-party integration like Klue is compromised, attackers can leverage existing refresh tokens to bypass multi-factor authentication and traditional login monitoring.

### The Hypothesis
We hypothesize that an adversary is using compromised OAuth refresh tokens from the Klue supply chain attack to maintain persistent access to Salesforce environments. This activity will originate from non-standard infrastructure and will be followed by automated API activity used for discovery or exfiltration.

### How the Hunt Flows
The hunt begins by scoping the environment for any authentication events specifically associated with the 'Klue Battlecards' application. We use the `hb_auth_signin` surface to identify the users and source IPs interacting with this integration, providing a baseline of legitimate activity versus potential anomalies.

Next, the hunt generates leads through four parallel pivots. We match source IPs against known malicious infrastructure associated with the 'Icarus' group and perform stack-counting to find rare source IPs used by only a few users. Most importantly, we filter for authentication events that specifically utilize the 'OAuth Refresh Token' protocol subtype, which is the primary mechanism for the persistence described in the source report.

To confirm the nature of these logins, we pivot to the `hb_http_activity` surface. We look for automated REST API traffic targeting Salesforce query endpoints, specifically looking for user agents like `Python-urllib` or the string `5238`. Correlating these HTTP requests with the previously identified suspicious source IPs helps distinguish automated attacker discovery from standard user integration traffic.

Finally, the hunt uses an automated triage step to consolidate these findings. By comparing IP prevalence, token usage types, and API patterns, we can provide a high-confidence verdict on whether a specific session represents token abuse.

### What This Hunt Cannot See
There are inherent blind spots in SaaS log analysis. If the Salesforce Event Log ingestion is incomplete or if the 'OAuth Refresh Token' subtype is not correctly parsed into the `auth_protocol` column, the behavioral leads will be significantly degraded. Additionally, if an attacker uses high-reputation residential proxies or ephemeral VPS infrastructure that rotates faster than the hunt's lookback window, the correlation between authentication and subsequent API activity may be weakened.

### How to Run It
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime compatible with the `hunt.md` standard. Because this is a hunt rather than a static detection, it focuses on baselining and correlation rather than simple IP matching, making it more resilient to attacker infrastructure rotation.
