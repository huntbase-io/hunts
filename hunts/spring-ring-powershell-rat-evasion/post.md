# Hunting for Spring Ring PowerShell RAT and AMSI Evasion

Unit 42 recently published an analysis titled "Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams" (https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/). The report details a sophisticated vishing operation that targets employees via Teams calls to deliver a custom PowerShell Remote Access Trojan (RAT). This hunt is designed to identify the technical footprint of that RAT, specifically focusing on its delivery and defensive evasion mechanisms.

### The Hypothesis

Our hypothesis assumes an attacker has successfully used social engineering to convince a user to execute a malicious payload. The attacker then attempts to bypass the Antimalware Scan Interface (AMSI) in-memory by manipulating the `amsiInitFailed` flag to evade detection. Once evasion is established, the PowerShell process initiates a beacon to a campaign-specific command-and-control (C2) domain, such as `san-sid.com`, to receive further instructions.

### How the Hunt Flows

The hunt begins with scoping through DNS telemetry. We query `hb_dns_activity` for any host in the fleet that has resolved known Spring Ring C2 domains within the lookback window. This step provides an initial list of potentially compromised endpoints to prioritize for the more intensive behavioral checks that follow.

Next, we examine process-level behavior on those scoped hosts using `hb_process_activity`. We look for PowerShell or Pwsh instances executing command lines that contain remote content download keywords like `iwr` (Invoke-WebRequest) or `downloadstring`. While these can be found in legitimate administrative scripts, their presence on a workstation that just resolved a known C2 domain is a significant indicator of the Spring Ring stager.

To identify defensive evasion, the hunt pivots to `hb_script_activity`. We specifically search for script blocks that contain the string `amsiInitFailed`. This flag is used in Campaign A of the Spring Ring operation to disable AMSI scanning by tricking the system into believing AMSI failed to initialize. This is a high-fidelity indicator because it is rarely used in legitimate production scripts.

Finally, we perform a network-wide baseline of outbound PowerShell connections using `hb_network_connection`. By identifying destinations where PowerShell is communicating that are rare across the environment (e.g., seen on fewer than three hosts), we can isolate the specific C2 infrastructure used in the attack, even if the domain names were recently rotated or modified from the original report.

### Blind Spots and Limitations

This hunt relies heavily on PowerShell Script Block Logging (Event ID 4104). If this logging is not enabled or if the logs are being cleared, the `amsiInitFailed` manipulation will not be visible in `hb_script_activity`. Additionally, without TLS inspection, we can identify the destination of the C2 traffic but cannot inspect the payloads or exfiltrated data transmitted over the encrypted channel.

### Running the Hunt

This hunt is provided as a `hunt.md` playbook. It is a structured, machine-readable format that can be imported into Huntbase or any other hunt.md-aware runtime. Because it uses multi-surface corroboration, it is more resilient to simple obfuscation than a static detection rule. We recommend focusing the hunt on user workstations where Microsoft Teams is standard and targeting users whose roles might be susceptible to help desk impersonation lures.

Source: Unit 42 — Spring Ring
