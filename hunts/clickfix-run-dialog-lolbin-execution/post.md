# Hunting for ClickFix Social Engineering via Windows Run Dialog

### Why this hunt

The Huntress team recently detailed a campaign called ClickFix in their article, "How Huntress Detects and Responds to a ClickFix Attack" (https://www.huntress.com/blog/fix-for-clickfix). This attack shifts the burden of execution to the user. Instead of delivering a malicious file that an EDR might block on write, the adversary presents a fake error message. This message directs the user to open the Windows Run dialog and paste a pre-copied command. Because the command executes directly from the user's interactive session, it often bypasses traditional perimeter and file-based defenses.

### The hypothesis

The intruder uses social engineering to trick users into pasting obfuscated commands into the Windows Run dialog, using explorer.exe to launch downloaders like finger.exe for payload retrieval. This bypasses many file-based detections because the initial malicious component is a string of text in the user's clipboard, executed through a trusted system process.

### How the hunt flows

The hunt begins by identifying every Windows host in the environment using hb_software_inventory. This scoping step ensures behavioral queries target systems where the Windows Run dialog is a standard interface. By narrowing the scope, we reduce the processing load and focus on the most likely targets.

The lead generation phase examines hb_process_activity for explorer.exe parentage. It looks for explorer spawning cmd.exe or common LOLBINs like finger.exe. The search specifically identifies caret obfuscation, such as "f^i^n^g^e^r", and social engineering strings used to hide the malicious command from the user’s immediate view.

An analyst or automated agent then evaluates the logic of these command lines. This phase checks for "for /f" loops used to execute retrieved data and specific social engineering padding like "push the enter key". This logic gate filters out legitimate administrative tasks that might use shells but lack these specific attack patterns.

Once a suspicious command is found, the hunt initiates parallel enrichment steps. It calculates the prevalence of the child process across the fleet using hb_process_activity to find rare binaries. Simultaneously, it searches hb_dns_activity for connections to known payload delivery domains like linkeders.net. Finding a rare process and a C2 resolution on the same host provides strong evidence of a successful intrusion.

The final triage phase synthesizes the evidence chain. If a host shows an explorer-spawned shell with caret obfuscation, the process is rare in the environment, and the host contacted a known C2 domain, the analyst confirms the verdict. This ensures we do not rely on a single indicator that the adversary could easily change.

### What the hunt cannot see

This hunt requires parent-process visibility to distinguish user-initiated Run dialog commands from other system activities. If telemetry does not track the relationship between explorer.exe and its children, the lead query will return high noise or miss the execution entirely. Additionally, a lack of DNS logging prevents confirmation that the finger.exe cradle successfully retrieved its payload.

### How to run it

This hunt is a hunt.md playbook. You can import it into Huntbase or any security platform that supports the hunt.md format to run these queries and automated triage steps across your environment. By following the structured steps, you can verify if users in your estate have fallen victim to this social engineering campaign.
