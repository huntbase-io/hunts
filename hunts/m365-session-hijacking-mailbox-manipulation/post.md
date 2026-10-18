# M365 Session Hijacking and Mailbox Manipulation Hunt

### Why This Hunt

Adversaries favor session hijacking over credential theft to bypass multi-factor authentication. The Huntress report, ClickFix to BEC in 24 Hours: Tragic Quadrant (https://www.huntress.com/blog/clickfix-bec-tragic-quadrant-doris), details how a fake browser update leads to Business Email Compromise (BEC) within 24 hours. After an attacker steals a session cookie, they access the target inbox without triggering new MFA challenges.

### The Hypothesis

An adversary has hijacked an authenticated Microsoft 365 session using stolen cookies, bypassing MFA to create stealthy inbox rules and perform fraudulent financial transactions. The adversary uses minimalist rule names to hide the diversion of sensitive emails while they execute invoice fraud.

### How the Hunt Flows

The hunt starts by querying M365 cloud activity for the creation or modification of inbox rules. We look specifically for rules with minimalist names like ".", "..", " ", or "z". These names are common in BEC attacks because they are easily overlooked by users in the Outlook interface. This step identifies the specific user accounts that might be under attacker control.

Once the hunt identifies a suspicious rule, an analyst or automated agent evaluates the lead. Not every minimalist rule name is malicious, but in the context of a potential BEC, this activity is a high-fidelity gate for the more resource-intensive steps that follow. If the rule is deemed suspicious, the hunt fanned out to investigate both authentication and mailbox impact simultaneously.

The hunt then investigates authentication and mailbox impact simultaneously. The first branch of the parallel investigation examines authentication logs for the flagged users. We look for session concurrency anomalies, such as a shift in the User-Agent string or a change in the source country while a session is active. A sudden move from a known corporate IP to a residential proxy or a different browser type suggests cookie theft.

The second branch of the parallel investigation searches for impact. We look for the technical side effects of BEC: the hard deletion of messages, emptying of folders, or the sending of unauthorized emails. Attackers often delete their own sent messages or incoming replies from victims to keep the legitimate user unaware of the ongoing fraud.

Finally, the hunt synthesizes these points—the suspicious rule, the session anomaly, and the destructive mailbox activity—into a single verdict. If the evidence aligns, the hunt provides an automated action to revoke all active M365 sessions for the user, which kills the stolen cookie.

### Blind Spots

This hunt relies on the Microsoft 365 Unified Audit Log (UAL). If UAL is disabled or if the tenant lacks the necessary licensing level for advanced audit features, the signals for rule creation and mailbox deletions are invisible. Additionally, Microsoft logs can experience a latency of several hours. An attacker moving at high speed may complete their objectives before the logs are available for the hunt to process.

### How to Run It

This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. It requires the `hb_cloud_api_activity` and `hb_auth_signin` surfaces, which represent standard M365 audit and sign-in logs. The hunt is designed to be run on a recurring schedule or as a response to endpoint alerts indicating potential cookie theft.
