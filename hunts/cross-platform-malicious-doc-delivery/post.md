# Cross-Platform Malicious Document and Script Delivery Hunt

### Why now?
Huntress recently published research titled [Post-DEF CON Phishing Uses Malicious Google Doc to Deliver Malware](https://www.huntress.com/blog/defcon-phishing-google-doc-malware), detailing a campaign that targets security practitioners via social media DMs. The attackers provide links to a Google Doc that contains a malicious sidebar. Depending on the visitor's operating system, the sidebar delivers different delivery packages, ranging from macOS "ClickFix" shell commands to Windows ClickOnce installers.

### The Hypothesis
An adversary is using social engineering to drive users toward a malicious Google Doc sidebar that executes platform-specific scripts. On macOS, this results in a `curl | zsh` execution pattern. On Windows, the sidebar triggers the ClickOnce deployment service or a PowerShell loader using `BitsTransfer` to stage follow-on payloads from attacker-controlled infrastructure.

### How the Hunt Flows
The hunt begins by scoping the environment to hosts with common web browsers installed. This ensures the subsequent, more intensive telemetry checks are focused on the primary entry points for these social engineering lures. 

Next, the hunt performs parallel evidence gathering. We stack-count DNS resolutions against the specific infrastructure identified in the research, such as `apple-googleapi.com` and `gapidriver.com`. We isolate rare resolutions to find the specific hosts that likely interacted with the phishing lure.

For macOS execution, we pivot to process activity to find instances where a shell interprets remote content directly from a pipe. This behavior, often called ClickFix, is a signature pattern of the delivery mechanism used to install stealers on macOS. 

For Windows execution, we look for two specific signals: the use of the ClickOnce service (`dfsvc.exe`) to fetch remote `.application` manifests and PowerShell script blocks that use `BitsTransfer` or `Invoke-WebRequest` to pull and execute content. These patterns match the loader logic observed in the Sleestak/phishing loader samples.

Finally, the hunt uses an agent to evaluate the combined evidence. By correlating DNS hits with subsequent shell or ClickOnce execution, we can distinguish between a simple phishing click and a successful host compromise.

### What the Hunt Cannot See
This hunt relies on endpoint telemetry from managed assets. If an unmanaged or personal device interacts with the lure, we have no visibility into the execution phase. Additionally, if PowerShell Script Block Logging (Event ID 4104) is not enabled, we may see the initial loader but lose visibility into multi-stage or obfuscated scripts that execute later in the chain.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any hunt.md-aware runtime. Because it is a hunt rather than a static detection, it is designed to baseline your infrastructure and help you investigate the rare signals that often accompany targeted social engineering campaigns.
