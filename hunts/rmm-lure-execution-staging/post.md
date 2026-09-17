# Hunting for RMM Lure Execution and Staging

### The RMM Problem
Remote Monitoring and Management (RMM) tools present a unique challenge for security teams. In their article [The dual-use dilemma: Rethinking detection for remote access tool abuse](https://redcanary.com/blog/security-operations/rmm-detection/), Red Canary highlights how adversaries leverage the inherent legitimacy of these tools to bypass standard security controls. Because IT teams often use these same binaries, a single alert on an RMM tool is frequently ignored or dismissed as shadow IT. This hunt is designed to move beyond point-in-time alerts by looking for the specific patterns of lure execution and staging that precede unauthorized RMM use.

### Hypothesis
We hypothesize that an adversary has gained initial access by tricking a user into executing a renamed RMM installer or phishing lure (e.g., themed as invoices or IRS statements). This lure then stages a secondary, rare RMM tool to establish persistent environment control.

### How the Hunt Flows
The hunt begins with a baselining phase using the `hb_software_inventory` surface. We first identify which RMM tools are already managed and expected within the environment. This step is critical; without knowing what is 'normal' for your IT or MSP teams, the subsequent steps will produce too much noise to be actionable.

Next, we pivot to `hb_process_activity` to look for lure execution. We search for specific file patterns, such as `ssa.msi` or various invoice-themed executables, particularly when running from user-writable directories like `\Downloads\` or `\AppData\Local\Temp\`. This identifies the potential point of entry where a user may have interacted with a malicious payload.

In the third phase, we use frequency analysis to identify rare RMM binaries. By stack-counting the execution of tools like ScreenConnect, NetSupport, or Syncro, we focus on instances appearing on only a handful of hosts. Broad usage across the fleet usually indicates an authorized tool, whereas rare usage in conjunction with a recently executed lure is a high-confidence indicator of an intrusion.

Finally, we corroborate these findings by examining `hb_script_activity`. We look for PowerShell download cradles (using `Invoke-WebRequest` or `Net.WebClient`) that specifically mention RMM product names. This links the process-level execution to the network-level staging behavior, providing a complete picture of how the tool was introduced to the host.

### What This Hunt Cannot See
No hunt is exhaustive. This playbook will likely miss adversaries who use reflective loading to run RMM tools entirely in-memory without touching the process list with standard names. It also lacks visibility in environments where DNS logging is unavailable to corroborate beaconing behavior. Finally, if an adversary has heavily modified the binary metadata or used a custom-compiled version of the tool, standard name-based filters may not capture the activity.

### Why This Is a Hunt, Not a Detection
A standard detection rule typically fires on a single indicator, such as an encoded PowerShell command. This hunt links a phishing lure to the execution of a rare RMM binary and corroborates it with script-based staging behavior across three distinct surfaces. This multi-surface approach allows an analyst to see the entire staging chain, providing the context necessary to distinguish an intrusion from non-standard IT work.

### How to Run It
This hunt is packaged as an open `hunt.md` playbook. It can be imported directly into Huntbase or any other `hunt.md`-aware runtime. Practitioners can tune the `lure_indicator` and `rmm_binary_indicator` parameters to match their specific environment or latest threat intelligence.
