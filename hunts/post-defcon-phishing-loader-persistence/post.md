# PowerShell Loader and macOS Persistence Hunt for Post-DEF CON Phishing

We are releasing a new open-source hunt design focused on a recent multi-platform phishing campaign. As reported by Huntress in their article, [Post-DEF CON Phishing Uses Malicious Google Doc to Deliver Malware](https://www.huntress.com/blog/defcon-phishing-google-doc-malware), adversaries are using social engineering lures tied to industry events to deliver loaders and stealers to both Windows and macOS workstations.

### The Hypothesis
Our hypothesis is that adversaries are successfully tricking high-value targets into executing malicious payloads through ClickFix-style lures. On Windows systems, this results in PowerShell loaders being executed directly into the temporary directory. On macOS systems, the infection leads to the installation of the AMOS (Atomic macOS) stealer, which establishes persistence through specific LaunchDaemon configurations to maintain access to sensitive user data.

### How the Hunt Flows
The hunt begins on Windows by examining the `hb_script_activity` surface. We are looking for specific PowerShell execution patterns that combine download commands (like Bitstransfer or Invoke-WebRequest) with immediate execution via the 'iex' (Invoke-Expression) alias. This step specifically targets the report's observation of a `sys.ps1` file being pulled into the user's local temp folder.

Simultaneously, the hunt pivots to macOS telemetry using the `hb_scheduled_job` surface. Here, we look for the presence of the `com.xdivcmp.plist` LaunchDaemon. This is a high-confidence indicator of AMOS stealer persistence. Because file names are easily changed, the hunt does not stop at simple name matches; it looks for these entries within the standard `/Library/LaunchDaemons/` path.

To corroborate these signals, the hunt employs a stacking technique on the `hb_file_activity` surface. We look for rare files (seen on three or fewer hosts) within the sensitive paths identified in the initial phases. This helps distinguish between legitimate system scripts and unique, attacker-controlled payloads that may have been renamed to evade basic detection rules.

The final investigative phase utilizes the `hb_network_connection` surface to correlate endpoint activity with known malicious infrastructure. We check for any outbound communication to the C2 IP addresses (86.54.25.213 and 192.253.248.181) identified in the campaign. This provides the necessary network context to confirm if a loader successfully checked in with its controller.

### What This Hunt Cannot See
There are two primary blind spots to consider. First, if PowerShell Script Block Logging (Event ID 4104) is not enabled on Windows hosts, the initial script-based detection will fail to capture the loader logic. Second, while we can identify the persistence mechanism of the AMOS stealer on macOS, we cannot confirm if data was actually exfiltrated from TCC-protected applications (like Notes or Keychain) without additional OS-level auditing of Transparency, Consent, and Control (TCC) logs.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It is a structured, machine-readable document that can be imported into Huntbase or any other hunt-aware runtime. By using the `hunt.md` format, you can automate the execution of the SQL queries across your fleet while maintaining a clear, auditable trail of your investigation steps. This approach ensures that the hunt remains consistent, repeatable, and easy to tune as new infrastructure or lures are identified in the wild.
