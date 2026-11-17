# Hunting Microsoft 365 Outage Phishing and Account Abuse

### Why now
Microsoft Security recently detailed a "High volume phishing campaign uses Microsoft 365 outage lures to target multiple industry sectors" (https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/). The adversary sends realistic notifications about service outages or security updates to induce users to click tracking links. These links lead to credential theft and subsequent business email compromise (BEC) activity. 

### Hypothesis
An intruder gains initial access by sending phishing emails that impersonate Microsoft 365 outage notifications. These lures induce users to click tracking links that lead to credential theft and subsequent unauthorized cloud API activity, such as mailbox rule manipulation or unauthorized application consent.

### How the hunt flows
The first phase uses a cheap lead query against Microsoft 365 mail telemetry. It searches for specific sender domains and subject lines associated with the service-health lures. This initial step gates the rest of the hunt to ensure we only spend resources on expensive telemetry when relevant lures exist in the environment.

If the lead query returns matches, the hunt fans out into a parallel search across two distinct surfaces. The first branch examines DNS activity to find hosts that resolved the campaign's known tracking and redirection domains. This provides evidence that a user actually clicked the link within the phishing email.

At the same time, the second branch searches cloud API logs for rare impact indicators. It looks for the creation of new inbox rules or OAuth application consents, filtering for operations that occur across only a small number of users. This step identifies the actual impact of the credential theft.

In the final phase, an analyst or automated agent correlates these three points: the delivery of the email, the interaction with the link, and the subsequent API abuse. This sequence confirms a successful account takeover rather than just a blocked phishing attempt.

### What this hunt cannot see
This hunt relies on the Microsoft 365 Unified Audit Log. If logging is not centralized or certain mailbox types are excluded, the lead query will not see the incoming lures. Furthermore, the hunt uses a fixed lookback window. If the adversary waits longer than 14 days between the link click and the API abuse, the correlation may fail depending on your local log retention settings.

### How to run it
We provide this hunt as an open `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any compatible runtime. Because it is structured as a hunt rather than a static detection, it handles the gated logic and cross-surface correlation natively. You can adjust the lookback parameters and sender domains if the campaign infrastructure shifts.

High volume phishing campaign uses Microsoft 365 outage lures — Microsoft Security Blog
