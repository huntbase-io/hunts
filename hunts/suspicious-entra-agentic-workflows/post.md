# Hunting for Entra Agent ID Abuse via macOS PowerShell Clients

### Why This Hunt Matters

Recent research by Red Canary, [Investigating suspicious AI workflows in Microsoft Entra Agent ID](https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-assistive-agents/), highlights a novel impersonation vector. Adversaries can trick users into granting `access_agent` scopes to malicious assistive agents. Once granted, these agents can act on behalf of the user, potentially bypassing traditional MFA by inheriting permissions through delegated consent. This hunt focuses on identifying the specific macOS-based tradecraft used to trigger these agentic workflows.

### The Hypothesis

We hypothesize that an adversary is abusing Entra Agent ID by leveraging a specific PowerShell client on macOS (version 7.6.1) to trigger malicious On-Behalf-Of (OBO) workflows. The hunt assumes the adversary has already secured user consent and is now actively impersonating the user to interact with the Microsoft Graph API via the Graph Command Line Tools application.

### How the Hunt Flows

The hunt begins by narrowing the environment down to hosts with PowerShell installed using the `hb_software_inventory` surface. This scoping step is necessary to isolate systems capable of running the reported trigger scripts, primarily focusing on macOS or developer-heavy segments where PowerShell might be common but requires closer scrutiny.

Next, the hunt pivots to endpoint network telemetry. We look for a highly specific HTTP User-Agent string (`PowerShell/7.6.1`) in `hb_http_activity`. This versioned UA was observed in the specific exploit chain. Identifying this string in traffic to Microsoft Graph endpoints provides a high-confidence indicator of the trigger mechanism in action.

The final phase correlates these endpoint triggers with cloud authentication events in `hb_auth_signin`. We monitor for successful, non-interactive sign-ins to the Microsoft Graph Command Line Tools application. By baselining the source IPs, we can isolate rare or non-corporate IPs that overlap with the specific PowerShell User-Agent activity, pinpointing the adversary's beachhead.

### Blind Spots

This hunt has two primary limitations. First, it relies on inferring OBO behavior through AppID and IP correlation because standard authentication logs may lack the specific `agentType` or `agentSubjectType` sub-fields that definitively label agentic traffic. Second, this hunt targets post-consent activity; if the initial 'Add delegated permission grant' event was missed in Entra audit logs, we only see the threat once the agent begins acting.

### How to Run This Hunt

This hunt is packaged as a `hunt.md` playbook. It can be imported directly into Huntbase or any security platform that supports the `hunt.md` standard. The playbook includes parameters for the specific PowerShell version and the Graph CLI Client ID, allowing for adjustments as new versions or target applications are identified in the wild.
