# Hunting for Salesforce Data Exfiltration via Compromised Klue OAuth Tokens

Third-party supply chain compromises often bypass traditional perimeters by abusing established OAuth trusts. Following the report by Datadog Security Labs, [Detecting the Klue supply chain attack in Salesforce](https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/), we have developed a hunt.md playbook to help teams identify if their Salesforce environment was targeted for data exfiltration via the Klue integration.

### The Hypothesis
An adversary leverages compromised OAuth refresh tokens from the 'Klue Battlecards' application to perform automated API calls against Salesforce query endpoints. This activity originates from known actor-controlled infrastructure and uses standard Python-based library user agents to harvest CRM data.

### How the Hunt Flows

The hunt begins with a scoping phase focused on the `hb_auth_signin` surface. We look for any authentication events specifically associated with the 'Klue' or 'Battlecards' connected applications. The goal here is not to find an alert, but to identify the specific users and source IPs that have active sessions via this third-party provider.

Once the scope is defined, the hunt pivots into a three-way corroboration phase. First, it checks `hb_network_connection` logs for any interaction with Icarus threat actor IP addresses documented in recent intelligence. Simultaneously, it inspects `hb_http_activity` for specific 'Python-urllib' user agents targeting the Salesforce REST query API. This identifies the 'how' and 'where' of the potential exfiltration.

To account for the possibility of the actor rotating their infrastructure or tools, the hunt includes a behavioral baseline. It calculates the prevalence of user agents querying the Salesforce API. By surfacing tools used by only one or two source IPs, we can identify novel or customized exfiltration scripts that do not match known signatures but share the same automated characteristics.

Finally, a triage step aggregates these signals. A combination of the Klue application context, suspicious network destinations, and rare automated API behavior provides a high-confidence verdict for remediation, such as token revocation.

### Blind Spots and Limitations
This hunt relies heavily on the visibility of HTTP metadata. If your telemetry lacks the full URL path, specifically the query parameters, it may be difficult to distinguish between generic API usage and specific data harvesting (e.g., SELECT FIELDS(STANDARD)). 

Additionally, there is a challenge in OAuth normalization. Without a specific field indicating the use of a 'Refresh Token' versus an 'Access Token', we cannot definitively prove a token was reused from a theft; we can only infer it based on the anomalous nature of the source IP and the client tool compared to the user's typical behavior.

### How to Run This Hunt
This playbook is formatted as a `hunt.md` file, an open standard for portable threat hunts. You can import this directly into Huntbase or any runtime that supports the hunt.md specification. It uses parameterized queries to allow for easy adjustment of lookback windows and actor indicator lists as new intelligence emerges.
