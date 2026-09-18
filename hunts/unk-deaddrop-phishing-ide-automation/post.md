# Hunting UNK_DeadDrop IDE Phishing and Malicious Repository Tasks

### Why This Hunt Matters

Recent reporting by Proofpoint in their article [Don’t Fear the Repo: UNK_DeadDrop Phishing Campaign Targets Developers](https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal) details a campaign where North Korean-aligned threat actors target developers with fake job offers. The lure involves cloning a GitHub repository that contains malicious `tasks.json` files. When a developer opens these repositories in Visual Studio Code or Cursor, the IDE automatically executes scripts that lead to credential theft and persistent access. This hunt provides a systematic way to verify if your developer estate has been targeted by these specific lures.

### The Hypothesis

We hypothesize that an adversary has successfully lured a developer into cloning a malicious repository, which subsequently triggered automated IDE task execution and the installation of a persistent VSIX extension masquerading as a legitimate service.

### How the Hunt Flows

The hunt begins by scoping the environment. We use software inventory surfaces to identify hosts where Visual Studio Code or Cursor are active, ensuring the investigation focuses on the relevant developer workstations where these IDE-specific attacks occur.

Next, we pivot to file activity logs. We look for the creation of specific directory and file names associated with the UNK_DeadDrop campaign. This initial signal indicates that a developer has interacted with a known malicious repository on disk, even if the execution hasn't been observed yet.

We then examine process activity for the execution of automated IDE shell tasks. We specifically look for instances where the IDE process (like Code or Cursor) acts as a parent to shell engines executing scripts from repository-local paths, such as `vendor/` subdirectories. This is a characteristic behavior of the campaign's task automation exploit.

Finally, the hunt checks for persistence via VSIX extensions. By analyzing file activity within the editor's extension directories, we look for rare, newly installed extensions that masquerade as Google services. We use stack counting to isolate unique installations that differ from the organization's baseline.

### Blind Spots and Limitations

This hunt relies heavily on file and directory creation auditing. If your EDR does not capture directory creation (specifically for `git clone` operations), the initial discovery phase may be limited. Furthermore, without script block logging for Bash or PowerShell, we can identify that a script was run from an IDE, but we cannot see the decoded content or the secondary C2 infrastructure being contacted without further forensic analysis.

### Running the Hunt

This hunt is provided as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any other `hunt.md`-aware runtime. It uses a series of structured steps to correlate activity across software inventory, file systems, and process trees, which is necessary because detecting a simple `git clone` or a standard IDE process is too noisy for a standalone detection rule.
