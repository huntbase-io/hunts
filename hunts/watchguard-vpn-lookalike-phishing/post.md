# Hunting for WatchGuard VPN Lookalike Phishing and Credential Theft

### Why Now

Recent research from Huntress — [Fake WatchGuard VPN Site Steals Credentials](https://www.huntress.com/blog/fake-watchguard-vpn-credential-phishing) — details a campaign where adversaries use SEO poisoning to lure users to malicious domains. These sites impersonate WatchGuard download pages and use a JavaScript modal to harvest credentials. Because the site eventually delivers a legitimate, signed installer, the user often remains unaware of the theft, and endpoint security tools rarely flag the activity.

### The Hypothesis

An adversary uses SEO poisoning to lead users to fake WatchGuard VPN download sites that harvest credentials via a JavaScript modal before delivering the legitimate, signed installer. This approach allows the attacker to satisfy the user's original intent while successfully stealing corporate credentials.

### How the Hunt Flows

The hunt begins by identifying every host that resolved one of the known lookalike or collector domains. This initial scoping step builds a candidate list and calculates the prevalence of these domains across the fleet. If only one or two hosts resolved a domain, it increases the likelihood of a targeted or successful phishing attempt.

Next, the hunt executes parallel searches for HTTP and network activity. It specifically looks for search engine referrals from Bing or Google that land on the lure domains. It also checks for direct network connections from browser processes to the reported collection IP addresses. An analyst uses this data to confirm whether a user actually navigated the phishing lure or if the DNS resolution was merely a background event.

In the final phase, the hunt correlates the phishing interaction with the delivery and execution of the WatchGuard installer. It searches for file creation events for the specific installer name and looks for process launches matching the WatchGuard company metadata. Finding this activity shortly after a visit to a lure domain provides a high-confidence signal of a completed attack chain.

### Blind Spots

This hunt lacks visibility into the contents of encrypted TLS traffic. While we can identify POST requests to the collection infrastructure, we cannot confirm if the user entered valid credentials without checking external identity provider logs or looking for subsequent anomalous logins. Additionally, if the EDR or proxy telemetry does not capture full HTTP URI paths, we must infer the interaction with the credential modal from the timing of the subsequent file download.

### How to Run This Hunt

This hunt is provided as a `hunt.md` playbook. It is a portable, structured format that you can import into Huntbase or any hunt.md-aware runtime. The playbook contains the logic to scope your environment for lookalike domains and correlate the full chain of redirection, collection, and payload execution. This allows you to verify credential theft even when the final payload is a legitimate binary.
