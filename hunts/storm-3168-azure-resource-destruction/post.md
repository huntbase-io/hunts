# Storm-3168 Automated Azure Resource Destruction and Recovery Inhibition

### Why This Hunt Matters

Microsoft recently detailed Storm-3168 (JADEPUFFER) in [Storm-3168: Agentic-driven cloud attacks using compromised service principals](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/). This adversary uses automated scripts to move from initial access to full resource destruction in minutes. Traditional detection rules often trigger on single resource deletions, leading to high noise. This hunt focuses on the speed and volume of the attack chain to distinguish malicious automation from legitimate administrative tasks.

### The Hypothesis

A compromised service principal executes an automated sequence of Azure resource discovery, mass deletion, and credential collection to facilitate a cloud-native ransomware operation.

### How the Hunt Flows

The first step scopes the investigation using `hb_auth_signin` logs. The query identifies service principals authenticating with the specific Python user agent observed in the Storm-3168 campaign. This narrows the field to principals running scripts rather than standard management tools.

The hunt then branches into a parallel analysis of reconnaissance behavior. One path calculates the volume of read operations across subscriptions, while the other stacks user agent prevalence to identify outliers. Automated discovery by an agentic script typically generates a significantly higher volume of API calls than a human administrator.

An automated triage agent evaluates these reconnaissance patterns. If the agent finds evidence of scripted discovery, the hunt pivots to `hb_cloud_api_activity` to search for destructive actions. This phase looks for a dense sequence of storage account and database deletions alongside `ListKeys` operations for storage accounts. These actions together confirm the ransomware objective.

If the hunt confirms malicious destruction, it routes to response actions. The workflow provides instructions to revoke the service principal's identity and begins an impact assessment to identify which resources require restoration from backups.

### What This Hunt Cannot See

Cloud audit logs do not always provide the full request metadata. If the logs lack specific API version details, the analyst cannot always distinguish between a failed SQL deletion caused by the actor's script and one caused by existing resource locks. Additionally, while the hunt identifies when an actor retrieves storage keys, it does not see if the actor used those keys to access and encrypt data within the storage containers without additional, high-fidelity storage logs.

### How to Run This Hunt

This hunt is an open-source `hunt.md` playbook. You can import it directly into Huntbase or any hunt.md-aware runtime environment. The playbook uses standard SQL to query Azure activity logs and requires access to cloud authentication and API surfaces.
