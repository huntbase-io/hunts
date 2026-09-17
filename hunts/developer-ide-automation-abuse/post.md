# Hunting for Developer IDE Automation Abuse (UNK_DeadDrop)

### Why now

Recent reporting by Proofpoint in their article [UNK_DeadDrop Phishing Campaign Targets Developers](https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal) details a campaign where adversaries lure developers into cloning malicious repositories. The threat actor leverages the `runOn: folderOpen` feature in popular IDEs like Visual Studio Code and Cursor to execute malicious code the moment a project is opened. This method bypasses many traditional warnings by hiding within legitimate developer workflows.

### The Hypothesis

We hypothesize that an adversary is successfully abusing these task automation features to execute platform-specific loaders, such as shell or VBS scripts, located in non-standard project directories like `vendor/` or `src/`. By identifying developers who have interacted with specific external lures and subsequently executed rare scripts, we can isolate successful infections of the UNK_DeadDrop campaign.

### How the Hunt Flows

The hunt begins by scoping the target population. We use software inventory data to identify hosts with VS Code or Cursor installed. This ensures we are focusing our analysis on the primary targets of the campaign and helps establish a baseline for what 'normal' development activity looks like on those specific endpoints.

The second phase looks for the execution of the infection chain's loaders. We specifically search for the launcher scripts identified in the report—such as `run-update.sh` and `run-update-hidden-launch.vbs`—spawning from IDE processes or system interpreters. Simultaneously, we perform a stack-count of any script execution from user-writable paths to identify renamed or modified versions of these loaders that appear on only a few machines.

The final phase correlates these execution events with network telemetry. We look for HTTP requests to the specific GitHub repository names and accounts associated with the campaign. This provides the necessary context to move from 'suspicious script execution' to 'confirmed compromise' by linking the behavior directly to the known external threat source.

### Blind Spots

There are two primary blind spots to consider. First, if the organization's web proxy strips URL paths for privacy reasons, we may see connections to `github.com` but lose visibility into the specific malicious repository names. Second, if the EDR does not capture the full command-line arguments for parent processes, we may find it difficult to definitively prove that a script was spawned by the IDE's automation engine versus a manual user action in an integrated terminal.

### Why this is a Hunt

A simple detection rule might alert on a script named `run-update.sh`, but such rules are prone to high false-positive rates in developer environments where update scripts are common. This hunt is distinct because it combines three disparate surfaces: software inventory (scoping), rare process execution (behavior), and network pathing (correlation). It focuses on the intersection of these events to find targeted activity that a single-surface rule would likely miss or drown in noise.

### How to Run It

This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any other `hunt.md`-aware runtime for execution. It is designed to be run against EDR and software inventory logs with a recommended lookback window of 14 days.
