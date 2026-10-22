# Identifying Portable Interpreter Staging in Amazon-Themed ClickFix Campaigns

### Background

Recent activity highlights a campaign using Amazon-themed lures to deliver infostealers. Huntress detailed this in their report, [Amazon-Themed ClickFix Campaign Serves Up Finger-Licking Malware](https://www.huntress.com/blog/amazon-clickfix-finger). The adversary lures users into executing a command that eventually stages portable interpreters to bypass security controls. This hunt focuses on the activity following that initial execution.

### The Hypothesis

An adversary is deploying portable Node.js and IronPython interpreters to user-writable directories to execute obfuscated Doina loaders and Lumma infostealers. These interpreters provide a stable environment for the malware to run while avoiding the need for pre-installed dependencies. By placing them in paths like ProgramData or Temp, the adversary attempts to hide among the noise of temporary application files.

### Phase 1: Identifying Suspicious Execution

The hunt begins by monitoring for specific interpreter names, such as node.exe or ipyw32.exe, running from unusual locations. Normal installations typically reside in Program Files. Execution from \\ProgramData\\, \\Users\\Public\\, or \\Temp\\ suggests a portable runtime dropped by a script. This first query provides a broad list of candidates that may include legitimate developer tools or background update processes.

### Phase 2: Corroboration via Rarity and Network

The second phase uses two parallel queries to refine the results. One query performs fleet-wide stack counting on the process paths. It isolates paths that appear on only a few hosts, which often indicates a malicious staging directory like NodeView rather than a company-wide deployment. This step filters out noise from developer workstations that might use portable environments legitimately.

Simultaneously, the hunt checks for network telemetry linked to the campaign. It looks for HTTP requests to barbecue-themed domains such as grillmasterchef.com or specific URI paths like /timer6local. Finding a host that runs a rare interpreter and communicates with these domains provides high-confidence evidence of a successful ClickFix infection.

### Phase 3: Forensic Triage and Action

An analyst reviews the correlated evidence to reach a verdict for each host. The goal is to confirm if the interpreter execution coincides with the malicious network hits. If confirmed, the playbook directs the analyst to isolate the host and collect artifacts from the staging directory. This includes checking for Cyrillic characters used to bypass Python decoding or inspecting index.js for reflective DLL loading patterns.

### Blind Spots and Limitations

This hunt depends on endpoint process telemetry and HTTP logging. It cannot see activity on unmanaged assets or shadow IT where no agent exists. Additionally, while we see the initial HTTP handshake to the C2, Lumma Stealer often transitions to websocket communication for ongoing monitoring. The contents of these websocket frames remain invisible to standard HTTP telemetry, though the initial handshake remains a reliable indicator.

### How to Run This Hunt

This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to automate the collection and correlation steps. Because Node.js and Python execution can be noisy in technical environments, we designed this as a hunt rather than a static alert to ensure analysts only spend time on rare, correlated events.
