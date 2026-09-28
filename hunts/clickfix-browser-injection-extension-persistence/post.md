# Hunting ClickFix Browser Injection and Tampermonkey Persistence

### Why This Hunt

Adversaries behind the ClickFix campaign are moving away from operating system payloads and focusing on the browser. As detailed by Cisco Talos in [ClickFix moves into the browser: Cryptocurrency theft with Google-hosted C2](https://blog.talosintelligence.com/clickfix-moves-into-the-browser/), attackers use social engineering to trick users into manually executing malicious code or installing extensions. This shift bypasses many endpoint detection rules that look for process hollowing or unusual child processes. Confirming the integrity of the browser session is now a prerequisite for financial security.

### The Hypothesis

An intruder has used a social engineering lure to trick a user into manually injecting a JavaScript loader or installing a malicious Tampermonkey script that facilitates persistent cryptocurrency theft via the Google Visualization API.

### How the Hunt Flows

The hunt begins by scoping the environment for the Tampermonkey extension. While the extension is legitimate and used by many practitioners, it serves as the primary persistence mechanism for the malicious scripts in this campaign. Narrowing the scope to hosts with this extension reduces the data volume for subsequent steps and focuses efforts on the most likely targets.

Next, the hunt correlates delivery signals with execution in a parallel triage phase. It searches for HTTP traffic to known lure domains like Google Docs and Paste.sh, specifically looking for the specific path patterns or document IDs used in the campaign. Simultaneously, it examines script activity for patterns associated with the Google Visualization API (Gviz). The ClickFix loader uses the Gviz API for command and control by pulling data from attacker-controlled Google Spreadsheets.

An analyst then triages these early signals to find hosts where a lure visit was followed closely by a Gviz script execution. For these high-interest hosts, the hunt enters a follow-on phase to investigate persistence and collection behavior. It identifies file modifications within the Tampermonkey storage directories, which confirms that the loader successfully installed a persistent user script.

Finally, the hunt uses process prevalence to find the "tell" of a cryptocurrency skimmer. It identifies rare instances of clipboard manipulation tools like clip.exe or PowerShell's clipboard cmdlets. The adversary uses these tools to perform address swapping: when a user copies a destination wallet address, the skimmer replaces it with an attacker-controlled address. By filtering for low-prevalence commands, the hunt separates malicious activity from standard administrative scripts.

### Blind Spots

This hunt has two primary limitations. First, if a user injects the script directly into the browser's memory via the navigation bar or console without triggering persistence, the activity might leave no footprint on the monitored surfaces. Second, the hunt can identify that Tampermonkey is writing to its database files, but it cannot inspect the actual script text inside extension-managed storage without specialized forensic tooling or manual profile auditing.

### How to Run It

This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. The playbook uses structured queries to walk an analyst through the correlation of web, script, and file evidence to confirm a browser-level compromise and initiate containment.
