# Hunting for Seasonal Medicare Open Enrollment Social Engineering

### Why this hunt matters

Open Enrollment for Medicare occurs annually between October 15 and December 7. This period creates a surge in legitimate traffic to healthcare portals, which provides an ideal window for adversaries to deploy seasonal lures. A recent report by ESET, [Medicare scam calls, texts and ads: What to watch for this Open Enrollment](https://www.welivesecurity.com/en/scams/medicare-open-enrollment-season-scams/), explains how scammers use deceptive ads and lookalike websites to harvest sensitive personal and medical data. Detecting this activity via simple keyword alerts usually results in overwhelming false positives because legitimate usage shares the same terminology. This hunt addresses the problem by correlating the initial lure visit with downstream data submission and credential monetization.

### The hypothesis

An adversary uses lookalike domains during the Medicare Open Enrollment season to harvest personal and medical data via social engineering. They then use these stolen credentials to access sensitive health and banking portals for financial fraud or identity theft.

### How the hunt flows

The first phase uses DNS activity to identify potential leads. The hunt queries for any domains containing the words medicare or healthcare that do not end in official .gov TLDs. It also filters out a list of known-good government reporting sites. This scoping step is low-cost and allows an analyst to quickly see which hosts in the environment are interacting with non-official healthcare infrastructure.

After an analyst reviews the DNS leads and identifies suspicious domains, the hunt proceeds to a parallel deep-dive. One branch of this analysis searches HTTP traffic for rare POST requests. It specifically looks for data being sent to domains that contain Medicare keywords but are not part of the legitimate government estate. This captures the moment a user submits sensitive information into a malicious web form.

The second branch of the parallel fan-out monitors authentication logs for those same scoped hosts. It tracks sign-ins to sensitive services including banking, insurance, and medical portals. By correlating a visit to a suspicious domain with a subsequent login to a financial service, the hunt identifies patterns where an adversary may be testing stolen credentials or moving from identity harvesting to monetization.

The final stage synthesizes these findings. An agent correlates the timing of the DNS lure interaction, the HTTP POST submission, and the authentication attempts. This provides a clear picture of the attack chain, allowing the team to distinguish a user who is simply researching health plans from one who has successfully been phished.

### What the hunt cannot see

This hunt has two primary blind spots. First, it does not inspect the payload of HTTP POST requests. Without TLS inspection or proxy body logs, an analyst can see that a user sent data to a suspicious site, but cannot confirm the presence of a Medicare number or Social Security Number. Second, the hunt is limited by the retention period of DNS logs. Because social engineering campaigns can persist for weeks, a user might interact with a lure before the current logging window, leaving only the downstream authentication behavior visible to the analyst.

### How to run it

This hunt is available as an open hunt.md playbook. It can be imported into Huntbase or any hunt.md-aware runtime. Because the activity is highly seasonal, we recommend running this hunt weekly during the Open Enrollment window to ensure rapid response to new lookalike domains.
