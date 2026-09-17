# Hunting OysterLoader via TextShell API Hammering Behavior

Recent research by Sekoia, [OysterLoader unmasked: the multi-stage evasion loader](https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/), details a sophisticated delivery mechanism for the OysterLoader (aka CleanUp) malware. The campaign uses trojanized versions of common IT utilities like PuTTY and WinSCP to deliver the TextShell packer. This packer is notable for its use of 'API hammering'—loading and unloading hundreds of legitimate Windows DLLs to overwhelm sandboxes and heuristic engines. Because these calls involve legitimate system modules, they are frequently filtered out of standard detection logic to prevent noise.

### The Hypothesis
We hypothesize that adversaries are delivering trojanized installers for IT utilities that execute the TextShell packer. This packer will be visible through excessive, redundant DLL load events and process hashes that are rare across the environment, typically originating from user-writable directories like Downloads or AppData.

### How the Hunt Flows
The hunt begins with scoping through `hb_software_inventory`. We identify endpoints that have recently installed or updated tools like PuTTY, WinSCP, or Google Authenticator. This provides a focused set of hosts for more intensive behavioral analysis, rather than scanning the entire fleet's module telemetry.

Next, the hunt pivots into a parallel analysis of process behavior and prevalence. We use `hb_module_activity` to find processes loading more than 60 distinct DLLs in a short window, which serves as a proxy for the packer's hammering technique. Simultaneously, we check `hb_process_activity` to identify if these utilities have hashes that appear on only one or two hosts, which is highly suspicious for standardized enterprise software.

We then enrich these findings using `hb_file_activity` to confirm if the suspicious processes originated from user-writable paths. The final stage involves an automated triage that correlates these three signals: a rare hash, an unusual installation path, and the signature 'API hammering' behavior. This correlation is what differentiates a legitimate but old version of a utility from a malicious loader.

### Limitations and Blind Spots
This hunt relies heavily on the frequency of module-load reporting. If the telemetry agent only snapshots loaded modules periodically rather than capturing the events, it may miss the 'hammering' if the packer loads and unloads modules quickly. Additionally, we must remain aware that sophisticated attackers may use stolen but valid certificates; a 'signed' status on the MSI does not automatically indicate it is safe.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime environment that supports the `hunt.md` standard. The playbook is parameterized to allow you to adjust the lookback window and the list of targeted software names based on your environment's specific footprint.
