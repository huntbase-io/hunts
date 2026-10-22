# Amazon ClickFix Finger Utility Abuse

### The Campaign

Huntress recently published a report titled [Amazon-Themed ClickFix Campaign Serves Up Finger-Licking Malware](https://www.huntress.com/blog/amazon-clickfix-finger). The campaign uses SEO poisoning to drive victims to fake Amazon login pages. Once there, the site prompts the user to fix a supposed error by pasting a command into their terminal. This command abuses a legacy Windows utility to fetch malware.

### Hypothesis

An adversary lures a user to a spoofed Amazon page and pastejacks a command that uses finger.exe to download malicious payloads from a remote domain.

### How the Hunt Flows

The hunt begins with a scoping phase on the DNS surface. It queries `hb_dns_activity` for resolutions to known campaign infrastructure, including domains like `orders-amazon.com.advancedfences.com` and various BBQ-themed URLS. This step identifies which hosts in the environment interacted with the initial lure.

Next, the hunt pivots to process activity to examine the behavior of the finger utility. It specifically looks for `finger.exe` executions that include an `@` symbol, which indicates a remote connection. It also checks for shell-escape characters such as `^`, `,`, or `-` that the adversary uses to obfuscate the command and bypass simple string-matching detections.

To catch variations that do not match known patterns, the hunt performs a prevalence stack. It counts every unique finger command line across the entire fleet and filters for those appearing on three or fewer hosts. Since finger is a legacy tool with almost no modern administrative use, rare command lines are high-probability indicators of suspicious activity.

Finally, the workflow synthesizes these leads. An analyst or agent verifies if a host resolved a malicious domain shortly before executing a suspicious finger command. This temporal correlation confirms the user was successfully pastejacked, allowing for immediate isolation of the host before the attacker deploys follow-on stealers like Doina or Lumma.

### Blind Spots

This hunt has two primary blind spots. First, most environments do not log traffic on TCP port 79. Without this network visibility, the hunt can identify that `finger.exe` ran but cannot confirm if the payload download succeeded or what content the remote server returned. Second, without specific clipboard monitoring, the link between the browser interaction and the manual command execution relies on timing rather than a direct chain of custody.

### How to Run This Hunt

This hunt is available as an open `hunt.md` playbook. You can import it into Huntbase or any hunt.md-aware runtime. It requires standard process and DNS telemetry. If you identify a malicious verdict, the playbook includes instructions to isolate the host and inspect the user's temporary directory for malicious scripts.
