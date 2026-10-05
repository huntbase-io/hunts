# Hunting for Cloud Identity Hijacking and Mailbox Persistence

### Why This Hunt Matters

Modern identity attacks frequently bypass multi-factor authentication (MFA) through session token theft or device code phishing. The Huntress Tragic Quadrant (https://www.huntress.com/blog/huntress-tragic-quadrant-cyber-threats) highlights these methods as primary drivers for business email compromise (BEC). Once an adversary gains access, they often establish persistence by creating inbox rules that redirect sensitive mail to hidden folders. This allows them to intercept invoices or internal communications without the user ever noticing the activity.

### The Hypothesis

An adversary has bypassed multi-factor authentication via session token theft or device code phishing and established persistence by modifying mailbox rules to hide intercepted communications.

### How the Hunt Flows

The hunt starts by filtering Microsoft 365 sign-in logs to find successful authentications that lack MFA or specifically use the device code flow. These events provide the initial list of accounts and source IP addresses. The query focuses on successful status codes to ensure we only follow through on sessions that the adversary actually established.

In the next phase, the hunt runs two checks in parallel. It monitors cloud API activity for the creation or modification of inbox rules. We specifically look for rules that move mail to low-visibility folders like RSS Feeds, Archive, or Conversation History. Simultaneously, the hunt inspects DNS activity on associated endpoints for resolutions to known phishing or token-harvesting domains like railway.app. This ensures we catch both the cloud-side persistence and the initial endpoint-based lure.

An automated agent then correlates these signals. If a user account shows an anomalous sign-in followed by stealthy mailbox manipulation or suspicious DNS lookups, the agent flags the account for triage. This multi-surface approach ensures that the hunt captures the progression from initial access to persistence, providing the necessary context for a response.

### Why This is a Hunt

We treat this as a hunt rather than a static detection because mailbox rules are ubiquitous. Many users and IT departments use rules to manage high-volume mail or automate workflows. Flagging every new inbox rule would create an unmanageable volume of false positives. This hunt requires the convergence of distinct signals: an unusual authentication method, post-authentication mailbox manipulation, and endpoint network indicators. This correlation provides the context needed to move from a suspicious activity to an active threat verdict.

### What the Hunt Cannot See

This hunt relies on the availability of Microsoft 365 Unified Audit Logs. If these logs are not collected or if the provider does not expose specific API operations, the hunt cannot observe mailbox rule changes. Additionally, the DNS check depends on a provided list of phishing domains. An adversary using unique, ephemeral, or private infrastructure may evade the network portion of this hunt.

### How to Run It

This hunt is an open hunt.md playbook. Analysts can import it into Huntbase or any hunt.md-aware runtime to execute the queries across their environment. The workflow includes a response branch to revoke all active refresh tokens for compromised accounts, followed by a manual task for analysts to verify the specific conditions of the modified rules.
