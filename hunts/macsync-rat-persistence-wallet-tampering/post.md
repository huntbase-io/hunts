# MacSync RAT Persistence and Crypto Wallet Tampering Hunt

The recent analysis by Huntress in their article [MacSync Stealer: How a Google Search for Claude Led to a macOS Infostealer](https://www.huntress.com/blog/fake-claude-macsync) details a sophisticated macOS campaign. It begins with "ClickFix" lures—social engineering that tricks users into executing malicious code under the guise of fixing browser issues. While the initial delivery domains change rapidly, the post-infection behavior remains relatively consistent. This hunt focuses on those durable artifacts.

Our hypothesis is that an adversary has established persistence on a macOS host using a Mach-O RAT and LaunchAgents. We also look for evidence of the RAT tampering with sensitive local files, such as cryptocurrency wallet applications or credential stores, to facilitate data exfiltration.

The hunt begins by scoping the macOS assets within the environment. This ensures we are focusing our resources on the correct platform, specifically looking at developer workstations or personal devices where users might interact with AI-related software lures or cryptocurrency tools.

We then pivot to looking for early-stage persistence indicators. This includes monitoring for modifications to shell configuration files like .zshrc and the appearance of the .mpwd credential store or the osalogging.zip archive. These files are central to the MacSync lifecycle and are highly unusual in standard operating environments.

Next, we analyze LaunchAgents. Adversaries frequently use these to maintain persistence across reboots. The hunt uses stack-counting to identify rare LaunchAgent plists and command lines. By filtering for entries found on only a handful of hosts, we can isolate the custom persistence mechanisms used by the RAT.

The behavioral analysis continues with a search for specific screen-capture helper flags. The MacSync agent utilizes specialized flags such as --tcc-only to bypass or leverage Transparency, Consent, and Control (TCC) permissions. Detecting these flags in process command lines provides a high-fidelity indicator of malicious screen scraping activity.

We also monitor for C2 connections using the known WebSocket patterns identified in the research. Specifically, we look for outbound traffic to known malicious IPs or unusual ports like 8443. These connections are the heartbeat of the RAT, providing the channel for exfiltration and command execution.

Finally, the hunt examines file activity within common cryptocurrency wallet paths, such as those for Ledger, Phantom, or MetaMask. We look for unauthorized rewriting or trojanization of these applications. This stage represents the "impact" phase where the adversary attempts to intercept keys or manipulate transactions.

There are two primary blind spots to consider. First, if the endpoint agent lacks Full Disk Access (FDA) on macOS, it may not be able to see file modifications within protected application bundles. Second, the RAT uses an embedded OpenSSL stack for WebSocket communication, which can make traffic inspection difficult for network-level tools that rely on system-provided certificates.

This hunt is provided as a hunt.md playbook. It is designed to be imported into Huntbase or any compatible runtime. Because this is a hunt rather than a static detection, it is intended to be run periodically to catch compromises that may have bypassed initial defenses.
