# Hunting Interlock PHP RAT Deployment and PowerShell Loaders

Recent reporting by The DFIR Report in their article [KongTuke FileFix Leads to New Interlock RAT Variant](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) highlights a shift in how the Interlock group maintains access. Instead of traditional compiled binaries, they are deploying a PHP-based Remote Access Trojan (RAT). This approach leverages the flexibility of the PHP interpreter, often bundled as a portable executable, to bypass standard security audits that might not flag a legitimate interpreter as inherently malicious.

### The Hypothesis
We hypothesize that an adversary is deploying this PHP RAT by using PowerShell web cradles to fetch the environment from Cloudflare tunnels. Once downloaded, the PHP interpreter is executed from user-writable paths like AppData. This behavior creates a distinct trail: a PowerShell process making external connections to a tunnel service, followed by the execution of a PHP binary in a non-standard location.

### How the Hunt Flows
The first phase of the hunt focuses on scoping. We look across the `hb_process_activity` surface for any instance of `php.exe` running from a user's profile directory. While PHP is a standard tool for developers, it is rarely seen running out of a workstation's AppData folder. This step identifies the initial pool of suspicious hosts.

In the second phase, we examine PowerShell telemetry. We specifically look for the 'web cradle' pattern: processes using `Net.WebClient` or `Invoke-WebRequest` to download content that is immediately piped into `IEX` (Invoke-Expression). The presence of `trycloudflare.com` in the command line or references to scheduled task deletion (`schtasks /delete`) serves as a high-confidence pivot point.

The third phase introduces fleet-wide rarity. We aggregate PHP execution paths across all endpoints to find binaries seen on only a handful of machines. Legitimate development environments like XAMPP or WAMP typically appear on multiple hosts within a dev team, whereas a RAT deployment is often unique to the compromised target. This helps filter out the noise of authorized software.

Finally, we enrich these findings with network telemetry. We look for outbound TCP/UDP connections to known Interlock fallback IPs or any subdomain of Cloudflare tunnels. Correlating a rare PHP process with these network signals provides the context necessary to confirm a true positive.

### Limitations and Blind Spots
This hunt relies heavily on command-line visibility. If an attacker uses sophisticated obfuscation within their PowerShell scripts, simple keyword matching on the command line may fail. To mitigate this, we recommend enabling PowerShell Script Block Logging (Event ID 4104). Additionally, this hunt cannot see activity on hosts where endpoint telemetry is not reporting; universal coverage of the workstation estate is a prerequisite for a successful hunt.

### Running the Hunt
This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any runtime environment that supports the `hunt.md` standard. By automating the correlation between PowerShell, the filesystem, and network events, it reduces the manual effort required to triage potential Interlock intrusions.
