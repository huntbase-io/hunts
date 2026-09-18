# Hunting for Linux Fileless Staging and Memory-Backed Execution Primitives

### Why This Hunt
Adversaries targeting Linux environments increasingly utilize fileless execution to minimize their forensic footprint and bypass traditional antivirus and EDR solutions that rely on file-on-disk events. A recent deep dive by Elastic Security Labs, titled [memfd_create Linux Fileless Execution](https://www.elastic.co/security-labs/threat-command/memfd-create-linux-fileless-execution), highlights how utilities like `memfd_create` allow code to reside entirely in RAM. Because these payloads are often ephemeral, the most reliable time to catch them is during the staging phase—when the code is first downloaded and piped into an interpreter.

### The Hypothesis
We hypothesize that an adversary is using common utilities (like curl or wget) or specific staging frameworks (like FENIX) to fetch malicious payloads and pipe them directly into a shell or interpreter. This activity will manifest as rare command-line patterns or script contents that reference memory-backed streams and shared memory paths, such as `/dev/shm` or `/proc/self/fd/`.

### How the Hunt Flows
The hunt begins by scoping the environment for hosts that have developer tools or common downloaders installed. By querying the software inventory surface, we identify systems capable of initiating fileless one-liners. This allows us to focus our analysis on high-probability staging points, though the hunt can be expanded if the inventory is incomplete.

Next, we pivot to process activity to look for known framework indicators and malicious packages. We specifically look for references to FENIX or specialized loaders like `sympy-dev`. This step uses path-agnostic matching to find these tools even if they have been renamed or moved to non-standard directories.

We then conduct a parallel analysis of behavior and content. We examine process command lines for rare interpreter pipe chains—situations where a downloader pipes output directly into a shell or language runtime. These are stack-counted across the fleet to isolate outliers. Simultaneously, we inspect script activity for specific primitives like `memfd_create` or usage of the `/proc/self/fd/` filesystem, which indicate memory-resident execution logic.

Finally, the results are triaged by an analyst or agent to determine if the activity is a legitimate administrative task or a staging attempt. If malicious activity is confirmed, the hunt includes an action to isolate the host and capture a memory dump before the volatile payload is lost.

### Blind Spots and Limitations
This hunt has two primary limitations. First, if the Linux kernel is older than 5.10.16, eBPF-based telemetry may not reliably capture the `memfd_create` syscall, making the initial file creation invisible. Second, without full script block logging, we may see that a pipe occurred (e.g., `curl | bash`) but remains unable to see the actual contents of the payload that was executed.

### Running the Hunt
This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any other runtime that supports the hunt.md specification. This format ensures that the logic remains vendor-neutral and portable across different telemetry sources.
