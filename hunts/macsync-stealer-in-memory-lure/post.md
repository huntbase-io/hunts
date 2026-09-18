# Hunting for MacSync Stealer In-Memory Lures and Credential Access

Recent reporting by Huntress in their article [MacSync Stealer: How a Google Search for Claude Led to a macOS Infostealer](https://www.huntress.com/blog/fake-claude-macsync) details a sophisticated macOS infostealer. The malware uses a 'ClickFix' technique, where users are directed to legitimate-looking AI conversation pages and tricked into running a curl command. This command executes a polymorphic zsh loader that delivers an in-memory AppleScript. This hunt was designed to find the specific footprint of this loader and the subsequent credential theft behavior.

### The Hypothesis
We hypothesize that an adversary is using malvertising lures directing users to legitimate AI domains to execute a polymorphic zsh loader. This loader likely delivers an in-memory AppleScript designed to phish for administrative passwords or request Full Disk Access (TCC) permissions, eventually staging stolen data for exfiltration.

### Hunt Flow
The hunt begins by scoping the macOS fleet to narrow the behavioral search. We look for the initial 'ClickFix' lure by identifying process command lines where `curl` fetches content and pipes it directly into a shell (`zsh`, `sh`, or `bash`). We specifically filter for instances where these commands reference known lure domains like `claude.ai` or suspicious archives like `osalogging.zip`.

Once potential loaders are identified, we pivot to AppleScript UI interactions. MacSync relies on `osascript` to display fake password dialogs or permission alerts. Instead of looking for a static string, we stack-count the types of dialogs and alerts across the environment. Rare patterns—those appearing on only a few hosts—are analyzed to separate legitimate system maintenance prompts from malicious phishing attempts.

To confirm the infection, we corroborate this behavioral evidence with file and network artifacts. We search for specific staging files such as the hidden `.mpwd` store or the `/tmp/osalogging.zip` archive. Simultaneously, we look for network connections to known C2 infrastructure. The hunt concludes by triaging the progression: a host showing the initial curl lure followed by rare AppleScript UI interactions and file staging is considered a high-confidence match for MacSync.

### Blind Spots and Limitations
This hunt relies heavily on process telemetry. If the endpoint monitoring solution does not capture the full command line of ephemeral shell sub-processes, the initial polymorphic loader may be missed. Additionally, since MacSync executes AppleScript in memory, we are limited to inspecting command-line arguments. Without script block logging for `osascript`, we cannot see the full logic of the scripts, making us dependent on observing specific strings like 'Safe Storage' or 'login keychain' within the process activity.

### How to Run This Hunt
This hunt is packaged as an open `hunt.md` playbook. It is a structured, machine-readable file that can be imported into Huntbase or any other `hunt.md`-aware runtime. By using this format, you can execute the logic across your macOS fleet, following the automated pivots and triaging the results based on the provided success criteria. This approach is intended to find the silent 'background loader' phase that traditional detection rules often overlook.
