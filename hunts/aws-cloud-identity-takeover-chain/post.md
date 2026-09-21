# AWS Cloud Identity Takeover Chain

### Why this hunt?
Managing a SOC for 100 separate projects requires centralized visibility to catch adversaries moving between cloud accounts. A recent article by Elastic Security Labs, "One SOC, 100 projects: running centralized alert triage on Elastic Security Serverless" (https://www.elastic.co/security-labs/blog/centralized-alert-triage-cross-project-search), describes how to manage this scale using cross-project search. We have developed a hunt that applies these concepts to the AWS Cloud Identity Takeover Chain, identifying hijacked accounts across a decentralized organization.

### Hypothesis
An adversary gains initial access to a cloud account by brute-forcing the console and performing a password reset. They then use that access to establish a presence and move across multiple projects in the organization.

### How the hunt flows
The first step inventories every AWS account recording activity to the hb_auth_signin surface. This scoping phase ensures subsequent queries cover all linked projects while excluding known administrative noise from automated systems.

The next phase identifies source IPs targeting users with high authentication failure volumes on the hb_auth_signin surface. Simultaneously, the hunt monitors the same surface for password modification markers—such as PasswordReset or ChangePassword—occurring within the same time window as the brute-force attempts.

An analyst then evaluates these early anomalies to find IPs that transitioned from failure to success. This logic filters out common brute-force noise by focusing on attackers who successfully changed a password, which indicates the shift from attempt to takeover.

Using these confirmed suspicious IPs, the hunt pivots to find successful logons across the hb_auth_signin surface for all 100 projects. It also examines the hb_network_connection surface for outbound traffic from those same IPs. This confirms if the attacker is interacting with other infrastructure or performing data exfiltration after logging in.

Finally, an analyst synthesizes the authentication success and network markers to confirm active exploitation. If a takeover is confirmed, the hunt provides steps to isolate the identity by revoking IAM sessions and deactivating access keys.

### Blind spots
This hunt focuses on authentication and network surfaces. It cannot see internal privilege escalation via IAM management events, such as PutUserPolicy or AttachUserPolicy, which are not captured in normalized authentication logs. Analysts must manually audit raw CloudTrail logs to determine if the attacker elevated their permissions. Additionally, the creation of new access keys for persistence remains a blind spot that requires direct management-plane visibility.

### How to run the hunt
This hunt is available as a hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format to execute queries against your centralized Elastic instance. By running this centrally, you maintain uniform security standards across dozens of independent cloud projects.
