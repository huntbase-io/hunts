# Hunting SANSAR Stealth and Evasive C2 Channels

### Why now
Elastic Security Labs recently published 0% GPU use: How SANSAR hides Linux cryptomining (https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware), detailing a sophisticated Linux-based mining operation. The SANSAR toolkit focuses on long-term persistence through stealth. It uses both a kernel rootkit and library shimming to deceive administrators and monitoring tools about system resource use.

### The hypothesis
An adversary deploys a Linux rootkit and modifies library wrappers to hide cryptomining while using Tor and external IP discovery services for orchestration. The toolkit relies on a kernel module named acpi_thermal_mgr to hook ftrace and hide its presence, alongside a modified libnvidia-ml library that falsifies GPU telemetry data.

### How the hunt flows
The hunt starts by scoping the environment for specific file artifacts. The first query searches file activity logs for the installation of the kernel module or the creation of the libnvidia-ml backup file. Because SANSAR moves these files during installation, their presence or temporary creation is a strong lead for compromised systems.

Once a host shows these file indicators, the hunt initiates two parallel behavioral checks. The first check examines DNS activity for a sequence of lookups to common IP discovery services like api.ipify.org or ifconfig.me. The SANSAR orchestrator uses these services to determine the external IP address of the host before it establishes a connection to the Tor network.

Simultaneously, the hunt looks for specific process execution patterns. The adversary uses a very particular nvidia-smi command format to query GPU names in a non-standard CSV layout. This command is a signature of the SANSAR orchestrator's logic for selecting mining targets. The hunt groups these commands by host to find rare or anomalous usage that deviates from standard administrative activity.

Finally, an analyst or automated agent evaluates the intersection of these surfaces. A host that exhibits the specific GPU query format alongside multiple IP discovery lookups and the presence of rootkit files receives a malicious verdict for immediate isolation.

### What this hunt cannot see
If the acpi_thermal_mgr.ko rootkit loads successfully and hooks the kernel auditing interface effectively, it may suppress or falsify the telemetry used in this hunt. In such cases, process and network events from the host will not appear in centralized logs. Additionally, SANSAR can use Lyrebird to tunnel Tor traffic through HTTPS bridges, which may bypass protocol-based network filters.

### Why this is a hunt, not a detection
A single detection rule for nvidia-smi queries or IP discovery lookups generates too many false positives in a standard Linux environment. This hunt is necessary because it correlates artifacts across three distinct surfaces — file system, DNS, and process execution — to confirm the specific presence of the SANSAR toolkit. It identifies the relationship between the setup phase and the behavioral C2 phase that isolated rules cannot easily link.

### How to run it
This hunt is provided as an open hunt.md playbook. You can import this file into Huntbase or any hunt.md-aware runtime to execute the logic across your Linux fleet. Ensure your telemetry includes file path activity and DNS query logging for the best results.
