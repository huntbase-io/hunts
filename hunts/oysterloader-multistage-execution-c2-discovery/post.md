# Hunting OysterLoader: Signed MSIs and In-Memory Multi-Stage Execution

### Why Now

Sekoia recently detailed the multi-stage execution chain of OysterLoader in their report, [OysterLoader unmasked: the multi-stage evasion loader](https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/). This loader, often used to deliver Rhysida ransomware, bypasses traditional security controls by using signed MSI files and complex in-memory packing. Our team developed this hunt to track the transition from legitimate-looking software installations to malicious memory-resident behavior.

### The Hypothesis

An adversary gains initial access via a signed MSI impersonating common IT tools like PuTTY, WinSCP, or AnyDesk. The installer executes a packer that employs API hammering and custom LZMA shellcode to inject a downloader directly into memory. This downloader then establishes command-and-control (C2) to deploy follow-on payloads such as ransomware or credential stealers.

### How the Hunt Flows

The first phase scopes the environment for recent installations of software commonly impersonated by OysterLoader. The hunt queries `hb_software_inventory` to find packages like PuTTY or WinSCP. While these tools are often legitimate, newly installed versions on hosts where they are rare provide a high-fidelity starting list for deeper inspection.

The second phase looks for execution and memory evasion indicators across the scoped hosts. We query `hb_process_activity` to find instances where `msiexec.exe` spawns unusual child processes or processes that do not exist on disk, suggesting shellcode injection. Simultaneously, the hunt checks `hb_module_activity` for unsigned or invalidly signed modules loaded into system processes like `explorer.exe` or `svchost.exe`, which occurs during the downloader stage.

The final phase pivots to identify post-exploitation activity. The hunt uses `hb_network_connection` to find outbound traffic from the suspicious processes to rare destination IPs. It then correlates this network activity with `hb_file_activity` to detect the impact of ransomware—specifically mass file modifications or the creation of extensions like `.rhysida`—and the access of browser credential stores.

### What the Hunt Cannot See

This hunt has specific visibility limits. It cannot directly observe the packer's API hammering techniques, such as the repeated calls to `RevokeDragDrop` or `GetDC`, because it does not use ETW or deep API monitoring. Furthermore, without direct memory permission visibility, we cannot see the exact moment the shellcode transitions to an executable (RWX) state. The hunt relies on the observable results of these actions, such as the resulting fileless process behavior.

### How to Run This Hunt

We provide this hunt as a `hunt.md` playbook. This format is designed for portability; it imports directly into Huntbase or any other `hunt.md`-aware runtime. Because this is a hunt rather than a single detection rule, it requires an analyst to evaluate the pivots between software inventory, execution evasion, and network prevalence to confirm an intrusion.
