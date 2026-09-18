# Hunting for REVSTEALER Masquerading and Gaming Credential Theft

Recently, the team at Elastic Security Labs published an analysis titled [REVSTEALER ramps up: analysis of up-and-coming infostealer](https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer), detailing a new threat targeting gamers and corporate users alike. REVSTEALER is notable for its use of VMProtect and masquerading to bypass traditional static analysis, followed by aggressive harvesting of credentials from platforms like Steam, Battle.net, and Roblox. We have developed a new `hunt.md` playbook to help practitioners identify this activity in their environments.

### The Hypothesis
We hypothesize that an intruder is executing REVSTEALER binaries masquerading as legitimate software (such as Slack, Blender, or qBittorrent) within user-writable paths. Once active, the malware profiles the host by enumerating installed software via the registry and harvests sensitive configuration files, eventually deploying secondary modules like XMRig for cryptomining or proxy tools for persistent access.

### How the Hunt Flows
The hunt begins with a scoping phase using software inventory surfaces. We identify hosts where targeted applications like Steam or Slack are already installed, as these environments are the primary targets for the stealer’s credential-harvesting logic.

Next, the hunt looks for the lead process. We pivot to process activity to find binaries using names like `Slack.exe` or `Blender.exe` that are executing from unusual locations such as `\Users\Public\` or `\Temp\`. This step filters out legitimate installations to focus on potential masquerading.

Once a suspicious process is identified, the hunt pivots into parallel behavioral checks. We examine file activity for rare access to specific gaming configuration files—such as `Battle.net.config` or `RobloxCookies.dat`—by the suspicious process. Simultaneously, we inspect registry activity for rapid enumeration of the Uninstall key, which indicates the malware is profiling the host's installed software.

Finally, the hunt looks for evidence of secondary impact. We search for the execution of known follow-on modules, including `softmanager.exe` (proxy) or `xmrig.exe` (miner), linked to the initial infection. This provides a complete picture of the attack from execution to resource hijacking.

### What This Hunt Cannot See
There are several blind spots to consider. If the masqueraded binary is deleted immediately after execution, file-based evidence may remain, but the lead executable might be missed if process auditing is not continuous. Additionally, if the stealer uses advanced memory-based techniques to bypass App-Bound Encryption via debugger injection, the hunt will see the file access but not the specific memory operations used for decryption. We also cannot see the specific logic behind the malware's FNV1a-based obfuscation without deeper binary analysis.

### How to Run It
This hunt is provided as a `hunt.md` playbook. You can import this file directly into Huntbase or any other `hunt.md`-aware runtime. It is designed to be a hunt, rather than a single detection, because the individual signals (like a process reading a registry key) are often too noisy on their own. The value lies in the correlation of masquerading with specific theft behaviors across multiple surfaces.
