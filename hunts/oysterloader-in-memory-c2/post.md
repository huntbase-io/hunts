# Hunting OysterLoader Fileless Execution and Downloader Beacons

### Why This Hunt Matters

Recent analysis by Sekoia in their report, [OysterLoader unmasked: the multi-stage evasion loader](https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/), highlights a sophisticated multi-stage loading process designed to bypass traditional static analysis. OysterLoader, also known as Broomstick, is frequently a precursor to Rhysida ransomware. Its ability to decompress its downloader stage directly into memory using a custom LZMA routine makes it a difficult target for standard endpoint rules. This hunt focuses on the artifacts of that in-memory execution and the specific network patterns used for stage retrieval.

### The Hypothesis

We hypothesize that an intruder is executing fileless code decompressed in memory using a custom LZMA routine. This activity is evidenced by processes running without backing files on disk (`on_disk = false`) that are simultaneously beaconing to domain fragments used for payload retrieval, often accompanied by anomalous null user-agents.

### How the Hunt Flows

The hunt begins at the endpoint, specifically looking at process activity. We filter for instances where the `on_disk` flag is false. This is a direct artifact of OysterLoader's TextShell packer and shellcode phase, which allocates memory and decompress the next stage without writing to the file system. We exclude common system noise to focus on suspicious processes like `explorer.exe` or `svchost.exe` behaving in this manner.

Next, the hunt pivots to network telemetry to find the downloader stage C2. We search for HTTP and DNS activity containing specific domain snippets identified in the Sekoia research, such as `pefile.pe`, `exp.name`, or `exports.append`. These snippets are part of the naming convention OysterLoader uses for its stage retrieval servers.

We further refine the network search by looking for rare occurrences of null user-agents. OysterLoader’s use of `InternetOpenW` often results in requests without a user-agent string. While some system services do this naturally, we use a prevalence filter to isolate hosts where this behavior is rare, increasing the likelihood that it corresponds to the downloader's activity.

Finally, a triage phase correlates these signals. We look for the co-occurrence of fileless process indicators and suspicious network beacons on the same host within a tight timeframe. This multi-surface approach reduces the false positive rate that would come from looking at fileless execution alone.

### What This Hunt Cannot See

This hunt has two primary blind spots. First, it requires endpoint telemetry that can report the `on_disk` status of a process (such as Osquery or Sysmon). If the loader executes on an unmanaged host or a host without these specific telemetry hooks, the loading phase remains invisible. Second, if the C2 communication is fully encrypted via TLS and the environment lacks proxy decryption, we lose visibility into the URL paths and user-agents, forcing a reliance solely on DNS and SNI data.

### How to Run This Hunt

This hunt is packaged as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any security platform that supports the `hunt.md` format. Because it relies on correlating multiple telemetry types (process and network), it is best run as a periodic hunt rather than a real-time detection rule to allow for proper baseline and prevalence filtering.
