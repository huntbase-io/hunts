# Hunting for Endpoint Credential Harvesting and Memory Dumping

### Why hunt for credential theft

Adversaries move quickly from execution to harvesting. Once they land on a host, they need credentials to pivot to higher-value targets. Recent analysis from Huntress in [Credential Theft: How Attackers Steal & Use Stolen Credentials](https://www.huntress.com/blog/credential-theft-expanding-your-reach) highlights how attackers use stolen cookies and memory dumps to bypass multi-factor authentication and gain persistent access. Standard detections often look for known file names or specific strings. This hunt focuses on the underlying behavior and the rarity of the tools involved.

### The Hypothesis

An adversary harvests credentials from local browser stores, LSASS memory, or Registry hives to facilitate lateral movement. This activity appears as rare processes executing from user-writable paths that perform sensitive file or memory access.

### Lead Process Analysis

The hunt begins by examining process activity for suspicious origins and command-line arguments. It filters for binaries running from folders such as Temp, Public, or Downloads. Simultaneously, the query flags command lines containing keywords associated with LSASS dumping or Registry hive exports. This phase identifies the initial set of actors that require deeper scrutiny based on where they run and what they say they are doing.

### Corroborating Prevalence and Behavior

The workflow then splits into two parallel tracks to confirm malicious intent. The first track baselines process prevalence across the entire fleet. It identifies binaries that appear on fewer than five hosts, which helps isolate transient attacker tools from common environment-wide software. The second track monitors file activity for interactions with sensitive browser databases. If a process that is not a known browser reads files like Login Data or cookies, the confidence in the harvesting attempt increases significantly.

### Evaluating the Evidence

An automated agent evaluates the combined results from the process and file queries. It weighs the rarity of a binary against its actions. A common administrative tool running from a standard path might be benign, but a rare binary from a user-writable path accessing the browser store or dumping LSASS memory triggers a malicious verdict. This correlation allows the hunt to find custom or renamed tools that do not match static signatures.

### Blind Spots

This hunt has two primary limitations. First, it relies heavily on file activity telemetry. If a host has file monitoring disabled, the hunt cannot see the interaction with browser profiles, leaving only process-based indicators. Second, advanced adversaries may use reflective loading to dump memory. If they inject code directly into a legitimate process and avoid standard command-line strings, the process-based lead queries will not capture the activity.

### How to Run This Hunt

This hunt is provided as an open hunt.md playbook. You can import it directly into Huntbase or any hunt.md-aware runtime. Because it uses fleet-wide stacking, run this against your entire estate to establish a clean baseline of what processes normally operate in user-writable paths. The design allows you to focus on high-value targets, such as IT administrator workstations, by adjusting the scoping parameters before execution.
