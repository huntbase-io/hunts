# Hunting ClickFix MSI Installers via ChatGPT Custom GPT Lures

### The Shift to High-Trust Lures

Attackers are moving away from easily blocked domains to high-trust environments. A recent report by Huntress, [Attackers Abuse ChatGPT Custom GPTs to Deliver RAT via ClickFix](https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat), describes a campaign that uses Custom GPTs to host social engineering lures. These lures redirect victims to a Google Sites page that prompts them to fix a "Service Availability" issue by running a PowerShell command. This command fetches a malicious payload from a decimal-encoded IP address.

### Hypothesis

An attacker redirects users from ChatGPT Custom GPTs to a ClickFix site, triggering PowerShell commands that download and install a malicious MSI from a decimal-encoded IP address.

### Phase 1: Scoping and Behavioral Leads

The hunt begins by identifying the Windows estate and narrowing the search to hosts with PowerShell activity. The first primary query searches process activity for PowerShell or Pwsh instances using the `Invoke-RestMethod` (irm) command targeting decimal-encoded IP addresses (e.g., 1614733393). This pattern is a high-fidelity indicator of the ClickFix delivery mechanism, as legitimate administrative traffic rarely uses decimal-encoded hosts in the command line.

### Phase 2: Assessment and Gating

Before running broader, resource-intensive queries, an analyst or automated agent evaluates the discovered command lines. This step confirms the lead by checking if the strings represent external infrastructure. If the command line matches the ClickFix pattern, the hunt proceeds to the corroboration phase. If no suspicious PowerShell activity exists, the hunt closes to save processing time.

### Phase 3: Corroborating the Chain

Once a suspicious lead is confirmed, the hunt performs a fan-out search across DNS and File surfaces. It searches for DNS lookups to `chatgpt.com` or `sites.google.com` originating from the suspect host to confirm the initial lure redirection. Simultaneously, it stacks MSI file creations in temporary directories across the environment. It flags any MSI files that appear on three or fewer hosts, such as `ISOSimple.msi`, which indicate the dropper has landed.

### Phase 4: Triage and Containment

The final phase evaluates the combined evidence. A host showing the sequence of a ChatGPT visit, a PowerShell decimal IP command, and a rare MSI creation receives a high-confidence malicious verdict. The hunt provides instructions to isolate the host immediately to prevent the subsequent DLL sideloading and Remote Access Trojan (RAT) execution.

### What This Hunt Cannot See

This hunt faces two primary blind spots. First, DNS visibility only confirms that a user visited ChatGPT; it cannot distinguish between a legitimate session and the specific Custom GPT path without full HTTP proxy logs. Second, the second-layer PowerShell script (e.g., `1777.ps1`) often uses shift-key obfuscation. While the hunt identifies the download, manual analysis of the script blocks is required to decode the specific final-stage behavior if the EDR does not automatically de-obfuscate it.

### How to Run This Hunt

This hunt is provided as an open `hunt.md` playbook. It can be imported into Huntbase or any hunt.md-aware runtime. It uses a structured approach to gate expensive queries behind a behavioral lead, making it suitable for regular execution across large estates.
