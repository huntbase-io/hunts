# Hunting for M365 Cloud Reconnaissance and Automated Data Collection

Recent research from Microsoft titled [Passkey-themed social engineering leads to identity and cloud compromise](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/) highlights a sophisticated campaign using Adversary-in-the-Middle (AiTM) techniques to bypass MFA. Once an identity is compromised, the attackers do not stop at entry; they use automated tools to map the victim's reach across the Microsoft 365 ecosystem. This hunt focuses on identifying that transition from initial access to internal reconnaissance and data collection.

### The Hypothesis
We hypothesize that an adversary, having secured a valid session through phishing, will systematically enumerate M365 applications and sensitive repositories. This activity likely involves automated Node.js-based tools that hit specific discovery portals—such as 'My Apps' and 'Microsoft Approval Management'—followed by high-volume file enumeration in SharePoint and OneDrive to identify and exfiltrate high-value data.

### How the Hunt Flows
The hunt begins with scoping the estate. We use software inventory data to identify hosts with Microsoft 365 or Office installations. This defines our primary user population and ensures the subsequent steps are focused on relevant identities likely to have active cloud sessions.

Next, we search for anomalous portal access sequences. We look for users hitting three or more distinct discovery portals in a short time window. Accessing portals like 'My Sign-Ins', 'Microsoft Account Controls', and 'Microsoft Approval Management' in rapid succession is a strong indicator of automated discovery rather than typical user behavior.

The hunt then parallelizes the corroboration effort. We establish a baseline for rare discovery portal access to see if the activity is truly anomalous for your fleet. Simultaneously, we analyze file activity for high-volume touches in M365 providers and check host-level DNS logs for connections to known phishing domains associated with this specific campaign. This three-pronged approach provides the context needed to distinguish a compromised user from an active power user.

Finally, we triage these patterns. By reviewing the combination of portal sequences and file volumes, we can reach a verdict on whether an identity is likely compromised and being drained by an adversary.

### Blind Spots and Limitations
There are two primary limitations to this hunt. First, file activity telemetry in the M365 provider often captures 'touches' or metadata requests. Without specific Microsoft Graph Activity Logs, confirming if a file was fully downloaded rather than just enumerated can be difficult. Second, if the initial phishing interaction occurred on an unmanaged personal device, we will miss the initial DNS and network indicators, meaning the hunt will rely entirely on the cloud-side behavioral footprint.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported into Huntbase or any runtime environment that supports the hunt.md specification. Because this hunt relies on correlating multiple surfaces—software inventory, authentication logs, file activity, and DNS—ensure your telemetry streams are synchronized for the requested lookback period.
