# Hunting for AI-Agent Orchestration in CI/CD Pipeline Hijacking

### The Shift to Machine-Speed Intrusions

The traditional timeline of an intrusion—days or weeks spent on lateral movement and reconnaissance—is being compressed into hours. A recent investigation by [Unit 42 — An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation](https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/) highlights a case where an attacker leveraged AI assistance to rapidly navigate a compromised environment. This shift requires a change in how we hunt: we must look for the patterns of automation and orchestration rather than individual Indicators of Compromise (IoCs).

### The Hypothesis

Our hypothesis focuses on the 'agentic' phase of an intrusion. We assume an adversary is using autonomous AI agents to perform rapid credential harvesting from secrets managers and exfiltrating cloud keys via CI/CD pipeline abuse. Because these agents operate via API and parallel execution, they leave a distinct behavioral footprint that differs from human operators—specifically, bursty, multi-identity authentication and high-frequency network requests to sensitive endpoints.

### How the Hunt Flows

The hunt begins by scoping the environment to DevOps and container infrastructure. We use software inventory data to identify hosts running tools like Jenkins, GitLab, Terraform, and Docker. These systems are the primary targets for an adversary seeking to pivot from local access to cloud-wide infrastructure control.

Next, the hunt pivots into parallel evidence gathering across three surfaces. First, we examine identity logs for 'parallel authentications'—instances where a single source IP successfully authenticates as multiple distinct users within a short timeframe. This mimics an AI agent testing multiple stolen tokens to map permissions. Simultaneously, we look for 'bursty' HTTP activity directed at secrets management APIs (like HashiCorp Vault) or AI model endpoints, which are often used by agents for further orchestration.

To corroborate these network and identity signals, the hunt looks for file-level activity on development hosts. We specifically target modifications to Infrastructure-as-Code (IaC) files, such as Terraform configurations (.tf). Unauthorized edits to these files are a high-confidence indicator that an attacker is attempting to plant backdoors or exfiltrate environment variables directly through the deployment pipeline.

Finally, the hunt checks for anomalous container persistence. We look for Docker restart policies set to 'always' or 'unless-stopped' for containers that were not part of the original stack. This helps identify the automated, redundant persistence mechanisms highlighted in the Unit 42 report.

### What This Hunt Cannot See

There are two primary blind spots to consider. First, if your environment lacks centralized audit logging for the internal operations of a secrets manager (e.g., identity-level logging within Vault), we may see the connection but not the specific secret that was accessed. Second, this hunt is less effective against agents that perform 'clean-up' by deleting ephemeral containers after use. If the container definition is deleted before the hunt runs, we will lack the configuration telemetry to flag it.

### How to Run It

This hunt is provided as a `hunt.md` playbook. It is designed to be imported into Huntbase or any security platform that supports the `hunt.md` standard for structured, human-in-the-loop investigations. Because this focuses on behavioral 'bursts' rather than single events, it is best run as a periodic hunt across your production and development enclaves.
