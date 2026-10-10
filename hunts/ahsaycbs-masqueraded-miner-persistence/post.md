# Hunting Masqueraded Cryptominers and Kernel Driver Evasion on AhsayCBS Servers

Recent research from Huntress — [AhsayCBS Flaws Exploit](https://www.huntress.com/blog/ahsaycbs-flaws-exploit) — details how unauthenticated RCE vulnerabilities in AhsayCBS backup servers allow attackers to drop webshells and deploy cryptominers. While a webshell is a clear indicator, the subsequent persistence and evasion techniques used by these actors are more subtle.

### The Hypothesis

The adversary establishes persistence on an AhsayCBS server by creating a fake Microsoft Edge service. They run a renamed XMRig cryptominer that monitors for Task Manager via PowerShell scripts to pause activity when an admin is watching. To optimize performance, the miner loads the WinRing0 vulnerable kernel driver and connects to external mining pools over non-standard ports.

### How the Hunt Flows

The hunt begins by identifying every host running AhsayCBS software. By scoping the search to these high-value backup servers, the analyst reduces noise from legitimate administrative tools and focuses on the systems most likely to be targeted by the unauthenticated RCE.

The second phase runs two queries in parallel to catch the adversary's dual-pronged persistence and evasion strategy. The first query looks for the creation of services like `MicrosoftEdgeUpdateSvc` that point to binaries in temp directories. Simultaneously, the hunt inspects PowerShell script logs for logic that stops and starts services whenever `taskmgr` appears in the process list.

Once the persistence mechanisms are identified, the hunt pivots to verify impact. It looks for the loading of the WinRing0 kernel driver, which miners use to access hardware MSRs for higher hash rates. This joins with network telemetry seeking outbound connections to known mining infrastructure and port 8029.

A final correlation step brings all indicators together. An analyst or automated agent reviews the full chain—from the fake service to the anti-analysis script and the kernel-level impact—to distinguish this malicious campaign from common administrative scripts or legitimate software updates.

### What the Hunt Cannot See

This hunt relies on PowerShell script block logging (Event ID 4104) to see the anti-analysis loops. If an attacker obfuscates the script or splits it across multiple blocks, a keyword-based search for `taskmgr` may fail. Additionally, if the adversary manual-maps the WinRing0 driver rather than using the standard Windows loader, the kernel extension telemetry may not capture the event.

### How to Run the Hunt

This playbook is provided in the `hunt.md` format. You can import it directly into Huntbase or any other runtime that supports the open hunt.md standard. It provides the structured queries and the logic required to correlate these disparate indicators into a single forensic verdict.
