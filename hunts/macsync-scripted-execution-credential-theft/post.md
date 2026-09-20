# Hunting MacSync Stealer Scripted Delivery and Credential Theft on macOS

### Why Now

The recent Huntress report, MacSync Stealer: How a Google Search for Claude Led to a macOS Infostealer (https://www.huntress.com/blog/fake-claude-macsync), details a campaign using malvertising to deliver infostealers to macOS users. The adversary uses a ClickFix lure, prompting users to paste a command into their terminal to fix a software error. This command is a one-liner that downloads and executes malicious scripts directly in memory. Our hunt provides a method to find these infections before the stealer exfiltrates keychains and browser data.

### The Hypothesis

An adversary tricks a user into running a curl-to-shell command to deploy MacSync Stealer on a macOS host. This loader then executes in-memory scripts to harvest credentials and stage them in a local zip file for exfiltration.

### How the Hunt Flows

The hunt begins with a scoping phase using hb_software_inventory. We identify macOS hosts running AI-related packages like Claude, Anthropic, or ChatGPT. Attackers target these users specifically with fake software updates or fixes for these tools. This scoping step allows the team to prioritize workstations where the lure is most likely to succeed.

The first lead query targets hb_process_activity to find the initial infection vector. We search for instances where curl pipes content directly to zsh or sh. Because developers often use one-liners for legitimate software management, this query is not a high-fidelity detection on its own. The hunt provides these results to an analyst who judges the parent process and specific command arguments to separate malvertising lures from admin tasks.

After an analyst confirms a suspicious process lead, the hunt gates into parallel evidence gathering across hb_script_activity and hb_file_activity. We search for rare script content containing specific daemon_function logic and AppleScript osascript commands. These in-memory blocks are the core of the stealer, used to bypass TCC prompts and steal the user keychain. Simultaneously, the hunt looks for the creation of /tmp/osalogging.zip, the hardcoded staging path the stealer uses to store loot.

This multi-surface pivot is why this is a hunt, not a single detection. A rule looking only for curl-to-shell commands creates excessive noise, while a rule looking only for /tmp/osalogging.zip misses infections where the file was already moved or renamed. By linking the initial lure to the rare in-memory logic and the staging file, we confirm the full infection chain.

### What the Hunt Cannot See

This hunt has two main blind spots. First, it depends on process command-line history in hb_process_activity. If the initial infection occurred outside the telemetry retention window, the lead query will return zero results. Second, the hunt requires comprehensive script block logging. If the macOS environment does not capture the content of AppleScript or shell blocks, the background logic used by the stealer remains invisible.

### How to Run It

To run this hunt, import the hunt.md playbook into Huntbase or any hunt.md-aware runtime. The playbook follows the gated flow described above, starting with broad scoping and narrowing down to confirmed evidence of theft. Analysts should focus on the timing between the suspicious curl execution and any rare script activity discovered in the fan-out phase.
