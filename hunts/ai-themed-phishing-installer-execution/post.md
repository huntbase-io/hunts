# AI-Themed Phishing and Malicious Installer Execution

### Background and Motivation

Recent research from Microsoft, [Detect and disrupt AI-themed attacks with Microsoft Defender](https://www.microsoft.com/en-us/security/blog/2026/09/10/detect-and-disrupt-ai-themed-attacks-with-microsoft-defender/), highlights a surge in campaigns leveraging the names of popular AI services like ChatGPT, DeepSeek, and Claude. Attackers are using lookalike domains and social engineering to trick users into downloading malicious installers that ultimately deploy information stealers such as Vidar. Because these installers are often renamed or frequently updated to evade signature-based detection, we have designed a hunt that focuses on the behavioral correlation between infrastructure lures and file activity.

### The Hypothesis

We hypothesize that adversaries are exploiting the current high trust in AI brands to deliver malicious payloads that execute from user-writable paths (like `Downloads` or `Temp`). These execution events will be preceded by DNS activity to lookalike domains that mimic legitimate AI service providers, indicating a successful social engineering redirection.

### How the Hunt Flows

The hunt begins with a scoping phase using `hb_software_inventory`. We identify hosts that already have legitimate AI software installed or have shown interest in AI tools. This allows us to create a high-priority cohort of users who are most likely to be targeted by, and potentially fall for, AI-themed phishing lures.

Next, the hunt pivots across three surfaces simultaneously. We examine `hb_process_activity` for executables with AI-related keywords running from non-standard paths like `AppData` or `Downloads`. In parallel, we use `hb_file_activity` to stack-count file creations in these same directories, filtering for rare files that appear on fewer than three hosts across the entire fleet. This helps distinguish a localized campaign from widespread, sanctioned software updates.

Finally, we correlate these endpoint signals with `hb_dns_activity`. We look for successful resolutions of specific lookalike domains—such as `chatgpt-plus.io` or `deepseek-install.net`—occurring within the same timeframe as the suspicious file activity. This multi-surface correlation is what makes this a hunt rather than a simple detection; we are looking for the context of the 'lure' and the 'payload' together.

### Blind Spots and Limitations

This hunt has two primary blind spots. First, without decrypted TLS visibility via `hb_http_activity`, we cannot see the full URI paths or the specific redirect chains that lead a user to the malicious download; we are limited to the DNS resolution. Second, the effectiveness of the scoping step depends on the freshness of the software inventory. If a user downloads a malicious installer before any legitimate AI software is registered by the system, they may not be prioritized in the initial cohort.

### How to Run This Hunt

This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any other `hunt.md`-aware runtime. To execute it manually, use the provided parameters to tune your `ai_keywords` and `lookalike_domains` based on the latest threat intelligence. Because it is designed to be a hunt, a negative result is still valuable—it confirms that these specific social engineering tactics are not currently bypassing your endpoint and network controls.
