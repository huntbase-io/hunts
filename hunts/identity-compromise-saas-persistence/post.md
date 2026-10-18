# Hunting for Identity Compromise and SaaS Persistence

### Why Identity is the Priority

Modern security leaders increasingly focus on identity as the primary defensive perimeter. In the article [What Cybersecurity Leaders Must Prioritize in 2027](https://www.huntress.com/blog/what-does-the-future-hold-for-todays-cybersecurity-leaders), Huntress emphasizes that resilience against identity-based threats is no longer optional. While Multi-Factor Authentication (MFA) remains essential, adversaries routinely bypass it through session hijacking and proxy-based techniques. This hunt addresses that gap by looking for what happens after the bypass.

### The Hypothesis

The adversary bypasses MFA using session hijacking or proxy-based adversary-in-the-middle (AiTM) techniques. Once they gain access, they establish persistence by creating malicious inbox rules to intercept sensitive communications or by granting consent to unauthorized OAuth applications to maintain access without needing the original credentials.

### How the Hunt Flows

The first phase filters identity provider logs for successful sign-ins where security controls are absent or obscured. The query identifies sessions that lack MFA or originate from known anonymizing proxies. This narrows the field to accounts currently operating under a weakened security posture.

Next, the hunt pivots into two parallel streams of analysis. The first stream performs geolocational stack-counting per user. By identifying locations seen on fewer than three unique IP addresses, the hunt highlights "impossible travel" or origins that do not match the user's historical profile. This helps isolate sessions that may be the result of a stolen session token used from a different region.

The second stream monitors cloud API activity for high-risk configuration changes. It specifically watches for the creation of new inbox rules or OAuth permission grants. These are the technical hallmarks of a Business Email Compromise (BEC) campaign, used to hide evidence of the intrusion or exfiltrate data.

Finally, an analyst or automated agent correlates these findings. A login from a proxy that occurs shortly before the creation of an inbox rule for "invoice" or "wire" provides high-confidence evidence of a successful compromise. This correlation reduces the noise associated with simple login alerts or common administrative changes.

### What the Hunt Cannot See

This hunt relies on the quality of telemetry provided by the identity provider. If the provider does not enrich logs with proxy intelligence, an adversary can mask their source IP without detection. Additionally, SaaS API logs often suffer from ingestion latency. In M365 environments, a 24-hour log delay means an attacker could establish persistence and exfiltrate data before the hunt identifies the activity.

### How to Run This Hunt

This hunt is published as a `hunt.md` playbook. You can import this logic directly into Huntbase or any runtime that supports the `hunt.md` format. Because this is a hunt, it focuses on the "why" behind the activity, allowing practitioners to pivot between authentication context and behavioral rarity rather than relying on static, noisy detection rules.
