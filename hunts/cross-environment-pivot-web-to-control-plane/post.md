# Hunting the Cross-Environment Pivot from Web Exploitation to Cloud Control Planes

### Why This Hunt Matters

Modern intrusions are increasingly multi-domain. According to the Unit 42 report, [Inside the Modern SOC: Defending the Cross-Environment Pivot](https://unit42.paloaltonetworks.com/soc-cross-environment-pivot/), approximately 43% of observed intrusions now span multiple environments. Traditional detection logic often fails here because it focuses on a single surface—an alert for a new cloud volume or a non-MFA login is often dismissed as noise. This hunt seeks to validate the entire pivot chain from an initial web exploit to control plane persistence.

### The Hypothesis

We hypothesize that an adversary has exploited a public-facing application to obtain credentials or session tokens, subsequently using those credentials to authenticate to SaaS administrative planes and modify cloud infrastructure for persistence or data staging.

### How the Hunt Flows

The hunt begins by narrowing the scope to assets that actually present a risk. We query vulnerability finding data to identify internet-facing systems with high-severity vulnerabilities (CVSS 7+). This provides a prioritized list of hosts to monitor for exploitation attempts rather than searching the entire fleet.

Once the vulnerable hosts are identified, the hunt analyzes HTTP activity for traffic patterns indicative of automated exploitation. We specifically look for source IPs that generate a high volume of 400-level errors followed by successful 200-level responses. This sequence often marks the transition from probing to successful breach.

In the third phase, we pivot on the suspicious source IPs to investigate identity logs. We look for successful SaaS sign-ins originating from the same IPs identified in the web exploitation phase. This connection is the 'cross-environment' bridge, indicating that the attacker is leveraging stolen credentials to move into the management plane.

Finally, the hunt examines cloud control plane logs for resource drift. We specifically look for new storage volume creations within the same temporal window as the exploitation and authentication events. This provides a clear view of the attacker's footprint within the cloud infrastructure itself.

### What This Hunt Cannot See

This hunt has two primary blind spots. First, it focuses on storage volume creation as a proxy for infrastructure changes. If an attacker establishes persistence through IAM role modifications, security group changes, or other non-storage resources, this hunt will not capture those specific actions. Second, the visibility into the SaaS pivot is limited by the ingestion of identity provider logs; if the attacker pivots into a SaaS platform not currently monitored by your security stack, the chain of evidence will be broken.

### How to Run This Hunt

This design is published as a `hunt.md` playbook. It is a structured, machine-readable format that can be imported directly into Huntbase or any other `hunt.md`-aware runtime. It uses SQLite-based queries against OCSF-formatted data to ensure portability across different security data lakes. Because this is a hunt rather than a static detection, it requires an analyst to review the final correlation to distinguish between legitimate administrator activity and a coordinated multi-domain intrusion.
