# Hunting for Rapid Phishing and Proxy-based Data Exfiltration

### Why this hunt

In the article [Inside Elastic InfoSec's agentic SOC](https://www.elastic.co/security-labs/blog/alert-triage-agentic-soc-elastic-workflows), the authors describe how automation reduces triage time from thirty minutes to three. This hunt applies that logic to the gap between identity compromise and data theft. Attackers often move faster than human analysts can triage individual SaaS login alerts. We need a workflow that links an authentication outlier directly to subsequent network anomalies.

### The Hypothesis

An adversary bypasses phishing-resistant MFA to gain initial access via a SaaS provider. They use this access to reach an internal host, establish a multi-hop proxy or tunnel for command-and-control, and exfiltrate internal data.

### How the Hunt Flows

The first phase queries Okta authentication logs for successful sign-ins from rare source IPs. It specifically looks for IP addresses that a user has not used in the previous thirty days. This provides a lead on potential credential theft or session hijacking.

An automated agent then assesses these sign-in events. It identifies the bridge between the SaaS login and the internal environment, such as a VPN session or an OIDC-integrated server login. If the agent finds a suspicious authentication lead, the hunt proceeds to the network phase.

The network phase runs two parallel searches. One query identifies hosts resolving rare domains at high frequency, which indicates a tunnel endpoint. The second query stacks outbound traffic by process and destination, looking for transfers exceeding 100MB.

The final triage step correlates the identity lead with the network signals. A final agent confirms if the suspicious login correlates with the proxy traffic and exfiltration volume. This correlation distinguishes an attacker's data theft from a legitimate user running a backup or sync tool.

### What this hunt cannot see

The hunt has three primary blind spots. First, it requires Okta connector logs; an adversary using a different identity provider or an unmonitored tenant will bypass the initial lead generation. Second, it relies on network fabric logs for accurate byte counts. If the environment only provides endpoint telemetry without traffic volume, the exfiltration query may fail. Third, the DNS query misses command-and-control if the adversary uses hard-coded IP addresses for their proxy tunnel.

### How to run it

This hunt is an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. It gates expensive network queries behind a verified identity lead to maintain performance across large datasets.
