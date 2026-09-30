# Hunting NeedyMantis Modular Sideloading and WebSocket C2

### Why NeedyMantis

Microsoft recently detailed [NeedyMantis: Unpacking a post-compromise malware family used in targeted operations](https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/). This framework provides adversaries with long-term persistence through modular components. The threat actor relies on DLL sideloading into legitimate applications and encrypted archives to hide their toolkit. Detecting this activity requires more than looking for known file names; it requires correlating staging paths, execution context, and specific C2 signals.

### The Hypothesis

An adversary has established long-term access by sideloading modular components into legitimate processes like Poedit or Vim, using encrypted archives staged in unusual directories to bypass detection. The adversary places these files in locations like ProgramData to maintain a lower profile while masquerading as standard administrative tools or third-party utilities.

### How the Hunt Flows

The first phase scopes the environment for staging activity. The hunt examines file creation and modification logs on the `hb_file_activity` surface. It looks for specific DLL names like winsparkle.dll, libcurl.dll, or vim64.dll written to directories such as ProgramData or Public Users. These locations are common for post-compromise staging but rare for these specific binaries during legitimate software installation.

Once the hunt identifies potential staging, it pivots to concurrent evidence gathering. The second phase uses the `hb_module_activity` surface to confirm execution. A query identifies instances where legitimate processes, such as Vim or Poedit, load these DLLs from the suspicious staging paths instead of their standard installation directories. This behavioral pivot separates legitimate software usage from a sideloading attack.

Simultaneously, the hunt checks the `hb_dns_activity` surface for C2 communication. It specifically looks for DNS resolutions of the known NeedyMantis domain, corp.tripswithengine.com. Because this domain is high-signal, any resolution originating from a host that also shows the sideloading pattern significantly increases the confidence of the finding.

In the final technical phase, the hunt performs a rarity baseline. It stack-counts the identified modules across the entire fleet. This ensures the results are not fleet-wide noise caused by a niche but legitimate administrative tool. The analyst focuses on modules appearing on only a handful of hosts, which is a hallmark of targeted modular malware.

### Blind Spots and Limitations

This hunt has two primary limitations. First, it faces a WebSocket visibility gap. While it can see DNS resolutions and persistent TCP traffic, it cannot inspect the WebSocket protocol stream itself. Without deep packet inspection, persistent 443 traffic might look like standard encrypted browser traffic. Second, it cannot see inside the staged archives. NeedyMantis stages components as extensionless, encrypted archives. While the hunt sees the archive's placement, it cannot confirm the contents without forensic decompression.

### How to Run This Hunt

This design is an open hunt.md playbook. You can import it directly into Huntbase or any hunt.md-aware runtime. The playbook includes the necessary queries and an automated triage agent to correlate the file, module, and network signals into a per-host verdict. If you find a match, the playbook provides instructions for isolating the host and performing forensic analysis on the ProgramData directory to recover the second-stage configuration.
