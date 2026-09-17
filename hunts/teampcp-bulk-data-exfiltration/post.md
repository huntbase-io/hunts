# Hunting TeamPCP Bulk Exfiltration from Compromised Cloud Credentials

### Why This Hunt Matters

Recent intelligence from Wiz, titled [Tracking TeamPCP: post-compromise attacks seen in the wild](https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild), details a campaign focused on deep post-compromise exploitation. Once TeamPCP gains access via leaked credentials, they don't just poke around; they move to automate the theft of source code and cloud secrets. This hunt focuses on that high-impact exfiltration phase, looking for the footprint of their automated toolsets.

### The Hypothesis

We hypothesize that an adversary using compromised Personal Access Tokens (PATs) or AWS keys will exhibit identifiable patterns during bulk exfiltration. Specifically, we expect to see authentication and API activity originating from known VPN (Mullvad) or VPS (Interserver) exit nodes. This activity will likely utilize a specific legacy User-Agent (`git/2.43.0`) and generate a volume of API calls—such as `git-upload-pack` or `GetSecretValue`—that significantly exceeds standard developer or administrative baselines.

### How the Hunt Flows

The hunt begins by scoping authentication events across cloud and version control providers. We pivot specifically on IP addresses associated with Mullvad and Interserver that have been observed in TeamPCP campaigns. This initial filter narrows the dataset to sessions originating from high-risk infrastructure.

Next, the hunt enters a correlation phase. We simultaneously look for three indicators: the presence of the `git/2.43.0` user-agent, a high frequency of sensitive API operations (cloning repositories or pulling S3/Secrets Manager data), and network-level evidence of data movement. By stacking these calls by source IP, we can identify automated exfiltration scripts that pull hundreds of secrets in seconds.

In the final phase, the hunt correlates these findings into a triage verdict. We examine the cumulative byte counts in network flow logs to confirm that the API activity resulted in actual data transfer to the suspicious IPs. This allows an analyst to move from a generic 'suspicious IP' alert to a confirmed exfiltration incident with a defined scope of lost assets.

### Blind Spots and Limitations

This hunt relies heavily on the visibility of source IPs within your audit logs. A significant blind spot exists if GitHub Enterprise IP logging is disabled; in such cases, we can identify *which* token was used, but not *where* the request originated, breaking the link to known malicious infrastructure. Similarly, if S3 Data Events (CloudTrail) or S3 Access Logs are not enabled, we may see the authentication but lose visibility into exactly which objects were stolen.

### Beyond Simple Detection

Standard detections often struggle with credential abuse because the actions themselves (cloning a repo, reading a secret) are legitimate. This hunt is effective because it moves beyond single-event alerts. It uses stack-counting to identify 'massive' volume and correlates that volume with specific client signatures and network byte counts to filter out the noise of legitimate engineering workflows.

### How to Run It

This hunt is packaged as an open `hunt.md` playbook. It can be imported directly into Huntbase or any security platform that supports the `hunt.md` standard. By following the structured queries, you can examine your estate for signs of TeamPCP activity over the last 14 days and initiate immediate credential rotation if malicious activity is confirmed.
