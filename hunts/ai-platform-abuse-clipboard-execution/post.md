# Correlating AI Platform Traffic with Malicious Clipboard-Driven Shell Execution

### Why Now: The AI Trust Boundary

Threat actors are increasingly exploiting the inherent trust users place in legitimate AI platforms. Recent research by Huntress, [The AI Attack Surface: How Threat Actors Abuse Trusted AI Platforms](https://www.huntress.com/blog/ai-attack-surface), details a shift toward using shared AI conversations and artifacts as delivery mechanisms for malware. By hosting lures on domains like `claude.ai` or `chatgpt.com`, attackers bypass many traditional web filters. These lures often use "ClickFix" social engineering, convincing users to copy and paste shell commands into their local terminal under the guise of fixing a technical issue.

### The Hypothesis

We hypothesize that an intruder is leveraging legitimate AI platforms to socially engineer users into executing malicious shell commands. This behavior will manifest as a sequence: a browser session with a known AI platform, followed by the execution of rare, highly obfuscated, or suspicious shell commands (e.g., pipes to bash, encoded PowerShell), followed by access to sensitive local identity files such as SSH keys, browser cookies, or login databases.

### How the Hunt Flows

The hunt begins by scoping the environment to systems capable of this attack chain. We look for hosts with a software inventory containing common web browsers and shell environments like PowerShell, Bash, or Zsh. This narrows the field to active user workstations where social engineering is most likely to succeed.

Next, we examine DNS activity to identify hosts interacting with major AI platforms or known malicious redirect domains mentioned in the Huntress research. We look for traffic to domains like `claude.ai`, `grok.com`, and `chatgpt.com`. While this traffic is common, it provides a temporal anchor for the next stage of the hunt.

In the third phase, we correlate that web traffic with process activity. We search for rare shell execution patterns that are characteristic of the ClickFix technique. This includes the use of `curl` or `wget` piped directly into an interpreter, or PowerShell using the `IEX` (Invoke-Expression) command. By using prevalence counting (stacking), we can filter out common administrative or developer activity, focusing only on command lines appearing on a very small number of hosts.

Finally, the hunt looks for evidence of credential or secret theft. We monitor for these same processes accessing sensitive file paths, such as `~/.ssh/`, keychain files, or browser-specific credential stores. The confluence of an AI platform visit, a rare shell command, and access to local secrets provides the high-confidence signal needed for a triage verdict.

### Blind Spots and Limitations

This hunt has two primary blind spots. First, without full HTTP URI visibility, we cannot confirm if a user visited a specifically malicious shared artifact or just a standard AI chat session. We rely on temporal correlation instead. Second, most endpoint telemetry does not provide clipboard monitoring. We cannot definitively prove a command was pasted from the browser into the shell; we must infer this sequence based on the timing and the rarity of the command itself.

### Why This is a Hunt, Not a Detection

A static detection for `curl | bash` or `Invoke-Expression` is often too noisy in developer-heavy environments. This is a hunt because it requires a multi-stage correlation—browsers, DNS, process prevalence, and file access—to build a story of social engineering. It moves beyond a single rule to identify the abuse of a trust boundary.

### How to Run It

This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any security platform that supports the `hunt.md` format. The playbook includes the specific queries and triage logic needed to identify these sequences across your fleet.
