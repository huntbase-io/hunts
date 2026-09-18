# Hunting Phishing Evasion via Invisible Unicode Tag Obfuscation

Microsoft recently highlighted a concerning evolution in phishing tactics in their article, ASCII smuggling crosses over from AI prompt injection to phishing evasion (https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/). This technique uses invisible characters to hide malicious content from security filters. Our hunt is designed to find evidence of these lures succeeding even when the initial delivery method remains hidden from endpoint logs.

### The Hypothesis
We hypothesize that an adversary is using invisible Unicode Tag characters to bypass email filters and deliver phishing lures for finance-themed domains. This bypass leads to initial access through user interaction with the lure, eventually resulting in command-and-control activity or credential theft.

### How the Hunt Flows
The hunt begins by scoping the environment to identify hosts with Microsoft 365 or Office components installed. Since the ASCII smuggling technique specifically targets users via email clients, narrowing our focus to these systems reduces noise and prioritizes the most likely targets for this campaign.

Next, we search for DNS resolutions to known phishing domains associated with the campaign. This step identifies systems that have already interacted with the reported infrastructure. We look for domains like guardiangrowthfunding.com and digitalcapitalboost.com, which were identified in the source reporting as active lures.

To identify novel or rotated infrastructure, we perform behavioral stacking. We look for rare DNS resolutions originating from Microsoft Office processes such as Outlook, Word, and Excel. Any domain resolved by these processes that appears on only one or two hosts across the entire fleet is treated as a high-priority lead for further investigation.

We then look for successful HTTP 200 responses to these same domains. A successful connection indicates the user likely bypassed any browser-level warnings and reached the landing page. We aggregate this data to provide a prioritized list of hosts for triage, focusing on those with both rare DNS activity and successful network connections.

### Blind Spots
This hunt has two primary blind spots. First, endpoint telemetry lacks visibility into the email body itself. We cannot confirm if the ASCII smuggling characters were present in the message; we can only observe the downstream network effects of the lure. Second, without TLS decryption, we cannot see the specific data posted to these phishing sites, such as harvested credentials or session tokens.

### How to Run It
This hunt is provided as an open hunt.md playbook. You can import this file into Huntbase or any hunt.md-aware runtime to execute the queries across your estate. The playbook includes automated triage logic to help weigh the evidence and prioritize the most suspicious host interactions for manual review.
