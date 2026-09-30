# Cloud Identity Hijacking and Azure DevOps Enumeration

### Background

Microsoft recently published "Beyond source code: A path to the keys to the kingdom", detailing an adversary tracked as Storm-3068. This group targets development and DevOps environments by first hijacking identities through self-service password resets (SSPR). Once they gain access, they perform automated enumeration of Azure DevOps resources and harvest credentials from developer workstations.

### The Hypothesis

An adversary hijacked a cloud identity using self-service password reset to perform automated discovery across Azure DevOps repositories and harvest Kubernetes configuration files. This approach allows the actor to bypass MFA or existing credentials and find a path into production clusters via the supply chain.

### Scoping the Environment

The hunt begins by identifying high-value targets within the fleet. We use software inventory data to list hosts running cloud management and container tools like kubectl, docker, and the Azure CLI. This creates a focused list of developer workstations, ensuring that subsequent file-level queries only run on hosts where Kubernetes configurations are likely to exist. Using software inventory instead of static host lists ensures the hunt remains effective as the engineering team grows.

### Finding the Lead

The first behavioral check looks for self-service password resets in identity logs. We treat an SSPR event as a low-cost lead. While many resets are legitimate, Storm-3068 uses this mechanism to take control of accounts. The hunt identifies these events over a 14-day window to provide the starting point for the investigation. We focus specifically on successful resets that result in a password change.

### Gating the Investigation

Because querying cloud API activity and file access across an enterprise is resource-intensive, this hunt uses a decision gate. An analyst or an automated agent reviews the SSPR events for suspicious patterns, such as resets from unusual locations or those performed by unexpected actors. The hunt only proceeds to the expensive phases if the identity takeover appears plausible. This prevents unnecessary volume in DevOps and endpoint logs.

### Correlating DevOps Discovery

Once a lead is qualified, the hunt pivots into Azure DevOps audit logs. We look for the suspect account performing high-volume enumeration of repositories, pipelines, and projects. The query identifies accounts that touch more than five distinct DevOps objects in a short period. This threshold suggests automated mapping rather than typical developer work. We group results by operation and user to highlight the most aggressive discovery behaviors.

### Checking for Credential Harvesting

In parallel with the cloud API check, the hunt examines file activity on the previously scoped developer hosts. We specifically look for the suspect user accessing Kubernetes configuration files, such as those named "kubeconfig" or "credentials". Finding a recently reset account suddenly enumerating DevOps repositories and touching K8s configs on a workstation provides a strong indicator of a Storm-3068 compromise. This step joins the identity lead with physical host activity.

### Blind Spots

This hunt has two primary limitations. First, it lacks visibility into the specific MFA method registered during an SSPR event; an attacker registering a new device looks very similar to a legitimate user in basic logs. Second, while we see that a file was accessed or a commit was made, we cannot see the actual secrets within the file content. These require manual verification of the repository history.

### Running the Hunt

This hunt is packaged as an open hunt.md playbook. You can import it into Huntbase or any compatible runtime to execute the gated flow. The design ensures you only spend your query budget on deep investigations when a clear identity lead exists. The playbook is self-contained and handles the pivots between identity, cloud, and endpoint surfaces automatically.

Beyond source code: A path to the keys to the kingdom: https://www.microsoft.com/en-us/security/blog/2026/09/29/beyond-source-code-a-path-to-the-keys-to-the-kingdom/
