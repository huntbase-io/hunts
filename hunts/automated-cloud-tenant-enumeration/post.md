# Post-Compromise Automated Cloud Tenant Enumeration and Data Collection

Recent reporting from the Microsoft Security Blog titled "Passkey-themed social engineering leads to identity and cloud compromise" (September 9, 2026) highlights a shift in post-compromise tradecraft. Once an attacker gains access to a cloud identity via session theft or phishing, they often move quickly to map the tenant's internal applications and file repositories using automated Node.js or Graph-based scripts. This hunt focuses on identifying those specific patterns of automated reconnaissance and subsequent data collection.

### The Hypothesis

We hypothesize that an intruder is using automated tools to rapidly discover internal applications and collect sensitive files from a compromised cloud identity. This activity is characterized by a specific sequence of sign-ins to M365 management portals—such as OCaaS, My Sign-Ins, and My Profile—that typically occurs faster and across more services than a standard user requires. We expect to see this behavior originating from rare or single-use source IPs and culminating in high-volume file access events in SharePoint or OneDrive.

### How the Hunt Flows

The hunt begins by establishing a scope of managed hosts that run M365 or Office software. This provides a baseline for where legitimate user activity usually resides, though the hunt remains broad enough to capture access from unmanaged or proxy-based infrastructure used by the attacker.

Next, we pivot to authentication logs to identify anomalous application discovery sequences. We look for single user-IP pairs that access a high variety of management and profile applications in a short window. This phase identifies the signature of automated discovery tools that iterate through the organizational application catalog to find high-value targets.

Simultaneously, we examine the prevalence of the source IPs involved. By stack-counting IPs that access these discovery applications, we can isolate those that are unique to only one or two accounts. This helps filter out common office egress points and focuses the investigation on infrastructure that may be specific to the threat actor or their proxy network.

Finally, the hunt corroborates these signals with file activity bursts. We look for a high volume of file reads or touches within SharePoint and OneDrive originating from the same users identified in the reconnaissance phase. This tie-back from the management plane to the data plane provides the evidence of intent needed to distinguish an active intrusion from administrative noise.

### What the Hunt Cannot See

There are two primary blind spots to consider. First, if the M365 tenant does not log all application IDs to the identity provider's telemetry stream, certain steps of the reconnaissance sequence may remain invisible. Second, social engineering often begins on personal mobile devices. Because these devices usually lack EDR telemetry, the initial link click and passkey interaction will likely not be captured; we are relying on the subsequent cloud-side activity to detect the breach.

### How to Run This Hunt

This hunt is provided as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime environment that supports the `hunt.md` standard. The playbook includes the necessary scoping, parallel processing for corroboration, and an automated triage step to help analysts prioritize results based on the correlation of recon patterns and data access volume.
