# Hunting IT Support Impersonation and WinRM Lateral Movement

### Why Now

Adversaries increasingly use legitimate remote-access tools to bypass perimeter defenses. The Microsoft Security Response Center recently highlighted these risks in the article From guidance to action: Security fundamentals that materially reduce risk (https://www.microsoft.com/en-us/security/blog/2026/09/17/from-guidance-to-action-security-fundamentals-that-materially-reduce-risk/). This hunt provides a technical path to find the behavioral chain associated with the CaptiveCrunch campaign, which uses these tools as a beachhead for lateral movement.

### The Hypothesis

An adversary hijacks a remote-support session to execute PowerShell, uses a portable Node.js runtime for command-and-control, and expands laterally via WinRM to domain controllers. They rely on the presence of existing support software to blend in with standard IT operations before staging malicious installers and moving toward internal infrastructure.

### How the Hunt Flows

The first phase inventories hosts running known remote-support software. The hunt uses these results to narrow the scope for behavioral analysis, ensuring that the heavy lifting focuses on the most relevant attack surfaces.

Next, the hunt examines process and script activity for early takeover behavior. It looks for administrative shells like PowerShell or CMD spawning directly from support binaries. It simultaneously searches script blocks for commands that download MSI files, which indicates the adversary is staging their toolkit after the initial takeover.

The final phase pivots to command-and-control and lateral movement. It uses stack-counting to find rare Node.js runtimes executing from user-writable paths like Temp or AppData, which are common for portable C2 agents. It then correlates these hosts with WinRM connections targeting sensitive internal IPs, such as Domain Controllers or Certificate Authorities.

An automated agent triages the results across all phases. It links the early shell execution to the later network traffic to provide a high-confidence verdict on whether a specific host represents a confirmed attack chain.

### What This Hunt Cannot See

This hunt has two primary blind spots. First, it relies on process names. If an attacker renames the portable Node.js binary to masquerade as a standard system process, the current filters will miss the execution. Second, while the hunt identifies WinRM connections to sensitive targets, it does not see the specific commands executed on those targets without WinRM Operational logging or deep packet inspection. An analyst must manually review the destination logs to determine the impact on the Domain Controller.

### How to Run It

This hunt is available as an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md specification. It runs as a multi-stage process that first scopes the environment and then triages the behavioral evidence into a final verdict.
