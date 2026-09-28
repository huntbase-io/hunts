# Hunting Metasploit Lateral Movement via WinRM and SMB Admin Shares

### Why now

Recent updates to common offensive frameworks, including those discussed in the [Metasploit Wrap Up: Payloads and Exploits, and Scanners, Oh my!](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-payloads-exploits-scanners), continue to refine how adversaries move laterally. When an intruder gains a foothold, they often use native Windows protocols to expand their reach. This hunt targets the specific intersection of authenticated remoting and administrative share abuse that allows Metasploit to deploy payloads and maintain a presence without relying on easily detectable shell commands.

### The Hypothesis

An intruder uses Metasploit to move laterally via WinRM and SMB and maintains persistence through direct process creation from user-writable paths to evade shell-based detection.

### How the hunt flows

The hunt begins at the authentication surface. The first query identifies successful WinRM or PowerShell Remoting (PSRP) logons across the environment. By focusing on these management protocols, the hunt creates a manageable list of source and destination hosts where administrative activity occurs. An analyst or automated agent then evaluates these logons to identify anomalous source IPs or unexpected user accounts that do not match known administrative patterns.

Once the hunt identifies a suspicious lead, it fans out to gather evidence from two different surfaces. The first branch examines SMB activity for access to administrative shares like ADMIN$ or C$. Metasploit modules often use these shares to stage payloads or execute commands remotely. The second branch looks at process activity, specifically searching for binaries running from user-controlled paths like AppData or Public. The query uses stack-counting to find rare parent-child relationships where these binaries are launched by non-standard parent processes, which often indicates a persistence mechanism.

In the final phase, an agent correlates the remoting leads with the SMB and process findings. This correlation confirms if a specific host was the target of a movement chain. If the agent finds matching evidence across multiple surfaces, the hunt provides a verdict for isolation and credential revocation.

### What this hunt cannot see

This hunt has two primary blind spots. First, it relies on the authentication surface having complete coverage of internal endpoints. If an adversary moves between hosts that do not report WinRM or PSRP logons to the central telemetry, the lead query will not trigger. Second, the persistence triage depends on historical command-line data. If the environment lacks process command-line logging, the hunt can identify a rare process but cannot determine the specific arguments used to establish persistence, potentially leading to a higher false positive rate during manual review.

### How to run it

This hunt is provided as a `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any other `hunt.md`-aware runtime. The playbook includes the necessary scoping queries and the gated logic required to run the more expensive process and SMB lookups only when a viable lead exists. You can adjust the `lookback_days` and `standard_parent_paths` parameters to fit your environment's baseline.
