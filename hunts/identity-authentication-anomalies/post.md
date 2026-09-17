# Hunting Identity and Authentication Anomalies in High-Volume Logs

### Why This Hunt

Credential theft remains a primary driver for data breaches, particularly as attackers shift from simple brute force to sophisticated Adversary-in-the-Middle (AitM) techniques. A recent analysis by Huntress, [Credential Theft: How Attackers Steal & Use Stolen Credentials](https://www.huntress.com/blog/credential-theft-expanding-your-reach), highlights how easily session tokens can be intercepted and reused. While many organizations rely on static MFA rules, these can be bypassed or rendered invisible depending on how a provider logs successful versus failed challenges. We designed this hunt to look for the traces left behind when an attacker successfully uses stolen credentials from a source that doesn't match the user's history.

### The Hypothesis

We hypothesize that an adversary is attempting to gain initial access via password spraying or is utilizing stolen session tokens. These actions manifest as successful logins from rare, non-resident source IPs and unusual multi-IP patterns for individual users. By examining the 'front door' of the organization, we can identify anomalies that traditional alerting might miss by looking at the relationship between IPs and identity over a rolling window.

### How the Hunt Flows

The hunt begins with a scoping phase focused on the `hb_users` surface. We identify active accounts that lack MFA or have unverified MFA status. These identities are prioritized because they represent the path of least resistance for password spraying or are the most vulnerable to simple credential harvesting.

Next, the hunt enters a parallel execution phase. One branch monitors `hb_auth_signin` for password spraying, looking for single source IPs that fail to authenticate against multiple unique accounts within the last 14 days. This provides context: if we see an IP spraying accounts and then later succeeding against one, that success is high-risk.

Another branch establishes a baseline of successful logins. It filters out common fleet IPs and established user habits to highlight logins from IPs with low prevalence. We are specifically looking for 'first-time' successes for a user that also have low frequency across the entire organization.

The final analytical branch checks for impossible velocity by identifying accounts that authenticate from multiple distinct IPs within a narrow window. This is a common indicator of session hijacking or the use of residential proxy networks where the attacker's source IP rotates frequently during the session.

### Blind Spots and Limitations

This hunt has two primary limitations. First, if the identity provider (such as AWS or M365) does not consistently populate MFA success or failure columns in the logs, we cannot distinguish between a successful AitM token-use and a standard login. Second, sophisticated adversaries use residential proxy networks to mask their traffic. If an attacker uses an IP that appears geographically similar to the user, a prevalence-based hunt may require additional telemetry, such as User-Agent consistency or HTTP activity, to confirm the anomaly.

### How to Run It

This is a `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime that supports the open hunt.md standard. The queries are written in a generic SQLite-compatible DSL and can be adapted to most SIEM or log management platforms that ingest authentication events. Running this periodically helps establish a 'clean' state for your identities and identifies gaps in MFA coverage.

