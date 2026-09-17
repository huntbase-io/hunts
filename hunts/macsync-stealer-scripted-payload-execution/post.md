# MacSync Stealer: Identifying Scripted Infostealer Execution

Recent research from Huntress, "MacSync Stealer: How a Google Search for Claude Led to a macOS Infostealer" (https://www.huntress.com/blog/fake-claude-macsync), details a campaign where macOS users are lured into executing terminal commands that install a sophisticated stealer. This hunt is designed to identify the footprint of this delivery mechanism across your fleet.

### The Hypothesis
We hypothesize that adversaries are using malvertising lures on legitimate-looking domains to trick users into running `curl`-to-shell commands. These commands deliver polymorphic ZSH scripts and AppleScript payloads that execute in-memory to extract browser secrets, SSH keys, and cloud tokens without leaving a traditional binary footprint on disk.

### How the Hunt Flows
The hunt begins by scoping the environment to macOS (Darwin) hosts. Because many developer workflows legitimately use shell scripting, the first technical phase targets the specific delivery pattern: `curl` commands where the output is piped directly into interpreters like `zsh`, `bash`, or `osascript`. This captures the initial "ClickFix" lure execution.

Next, the hunt pivots to `hb_script_activity` to inspect the contents of scripts executed on the host. We specifically stack-count scripts containing unique strings like `daemon_function` or base64-encoded heredocs. By applying a prevalence filter, we isolate rare scripts seen on only a few hosts, separating one-off malicious loaders from fleet-wide management scripts used by IT or DevOps teams.

Finally, we corroborate these findings with network telemetry. We look for connections from suspect processes to known MacSync delivery infrastructure (specifically `85.206.161.241`). This multi-surface approach—combining process command lines, script prevalence, and network history—allows us to verify the infection kill-chain even when the script hashes change between victims.

### What This Hunt Cannot See
There are two primary blind spots to consider. First, if your endpoint telemetry does not capture the content of `stdin` streams piped into shells, the `daemon_function` string and specific script logic will be invisible. Second, MacSync is aggressive about cleaning up its staging files, such as `/tmp/osalogging.zip`. If your file activity collection has high latency, the evidence of that archive may be deleted before it is recorded.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It is a portable, machine-readable format that can be imported directly into Huntbase or any other `hunt.md`-aware runtime. It uses declarative queries to automate the heavy lifting of stack-counting script blocks, allowing analysts to focus on triaging the high-confidence results.
