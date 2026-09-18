# Shai-Hulud: Hunting for IDE Hook Poisoning and Runner Memory Harvesting

Recent analysis by Datadog Security Labs on the [Shai-Hulud Framework](https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/) highlights a sophisticated shift in supply chain attacks: targeting the developer workstation's local lifecycle. Shai-Hulud doesn't rely on classic malware delivery; instead, it poisons the configuration files of IDEs and AI assistants to bootstrap a modular Bun runtime. 

Our hypothesis is that an adversary is using these poisoned hooks (specifically within VSCode or Claude Code) to establish deadman-switch persistence and extract sensitive secrets directly from the memory of GitHub runners. Because these actions often blend into legitimate development workflows, they are difficult to catch with static detection rules.

The hunt begins by scoping the environment to identify developer workstations and build servers. We use software inventory data to look for the presence of tools like Bun, VSCode, or Cursor, ensuring the subsequent steps are focused on high-risk surfaces where this framework is designed to operate.

The first phase of behavioral analysis targets the initial poisoning. We monitor file activity for modifications to IDE task definitions and AI assistant settings, such as `tasks.json` or `setup.mjs`. While some of these changes are routine, they serve as the entry point for the framework’s execution on folder-open events.

Next, the hunt pivots to gather evidence of the framework's post-exploitation activity in parallel. We stack-count scheduled jobs to find rare persistence monitors and analyze process activity for high-signal indicators of memory scraping. Specifically, we look for processes attempting to read from `/proc/pid/mem` belonging to GitHub runner workers—a technique used to harvest transient secrets.

Finally, we look for mass-reading patterns across cloud and identity credential files. By correlating these harvesting attempts with previous hook modifications, we can distinguish legitimate development activity from a coordinated Shai-Hulud infection.

There are known blind spots. If a poisoned repository is cloned into a directory excluded from EDR monitoring, the initial hook modification will be missed. Furthermore, Shai-Hulud’s persistence monitors are designed to self-terminate after 24 hours, meaning point-in-time snapshots of scheduled jobs may fail to capture the infection if the hunt is not run frequently.

This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any environment-aware runtime that supports the open hunt format to automate the correlation of these developer-centric signals.
