# Hunting Passkey-Themed Phishing and Identity Lifecycle Abuse

### Why Now

Passkeys represent a significant hurdle for attackers, but the security of the authenticator does not solve the security of the identity lifecycle. As detailed in the Huntress article [Passkeys Raise the Bar. Here’s Where Attackers Can Still Get In.](https://www.huntress.com/blog/passkeys-raise-the-bar-but-attackers-can-still-get-in), adversaries are already pivoting to exploit the moments when users enroll or recover their credentials. This hunt provides a structured way to find those pivots before an attacker establishes permanent residency in your environment.

### The Hypothesis

An adversary uses social engineering lures themed around passkey enrollment to trick users into authorizing a device-code login flow. Once they hijack the session, the attacker registers unauthorized authenticators and establishes persistence through cloud application grants, mailbox rules, or unapproved browser extensions.

### How the Hunt Flows

The hunt starts by scoping the environment for successful logins using the Device Code flow. While this protocol is necessary for certain headless or IoT devices, it is rare in standard business operations and is a primary vector for session hijacking in campaigns like EvilTokens. The first query isolates these events to create a list of high-risk users and hosts.

Next, the hunt gathers evidence from the identity lifecycle. It looks for MFA enrollment changes, credential resets, or recovery updates that occur shortly after a Device Code login. By stacking authentication protocols, the hunt also identifies users whose sign-in patterns have shifted significantly from their baseline. An automated agent or analyst then triages these findings to determine if a specific user likely fell for a social engineering lure.

For users marked as high-risk, the hunt pivots to investigate post-authentication persistence. It audits cloud API activity for new inbox rules, automated forwarding, or OAuth application consents that grant external access. Simultaneously, it inspects the software inventory on the user's host to find unapproved browser extensions. These extensions can be used to intercept sessions or even tamper with WebAuthn responses in real-time.

Finally, the hunt correlates the initial identity signal with the technical evidence of persistence. Connecting an unusual login protocol to a security modification and a subsequent cloud grant provides a high-confidence narrative of compromise that individual detection rules often miss.

### What the Hunt Cannot See

This hunt relies on audit logs and software inventory, which introduces two specific blind spots. First, if an attacker established persistence more than 90 days ago, those events may fall outside the retention window of the cloud API activity logs. Second, while the hunt identifies installed browser extensions, it cannot see in-memory browser hooks injected via other processes that might be used for advanced session tampering.

### How to Run it

This hunt is provided as a `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any other hunt.md-aware runtime. It uses SQLite-based queries against standardized surfaces to ensure portability across different security stacks. To begin, set your lookback window and provide your enterprise's list of approved browser extension IDs to filter out legitimate administrative tools.
