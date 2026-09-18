# Hunting for Kimwolf v7 Botnet Masquerading and ADB Propagation

### The Shift in IoT Botnets

Recent reporting from Unit 42 in their article [Kimwolf v7: An Evolution of the Kimwolf Botnet](https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/) highlights a sophisticated turn for the AISURU/Kimwolf malware. It specifically targets Android-based IoT devices, such as TV boxes, by exploiting unauthenticated Android Debug Bridge (ADB) access. Unlike noisy, self-propagating worms, Kimwolf v7 uses residential proxies to mask its propagation attempts, making simple network blocking less effective.

### The Hypothesis

We hypothesize that an adversary is actively using unauthenticated ADB access on port 5555 to install Kimwolf malware on exposed IoT assets. Once established, the malware maintains persistence and evades casual observation by masquerading its primary process as 'netd_service'—a name designed to blend in with legitimate Android system services like 'netd'.

### How the Hunt Flows

The first phase focuses on scoping. We identify Android and Linux-based hosts within the environment that match the botnet's target profile. Because Kimwolf targets specific architectures, we limit the initial data set to these platforms to reduce processing overhead.

The second phase looks for the execution of the masqueraded process. While a legitimate Android service named 'netd' is common, 'netd_service' is a known indicator of this v7 evolution. We query process activity logs for this specific string, capturing command lines and user contexts to differentiate it from standard system operations.

The third phase introduces file-level corroboration. The malware drops characteristic ELF binaries, specifically 'libdevice.so' and 'kernel.so'. We search for the creation or modification of these files on the hosts identified in the previous phases. Finding these binaries in conjunction with the 'netd_service' process significantly increases the confidence of the infection verdict.

The final phase examines the network surface for inbound ADB connections on port 5555. We look for a pattern where a host receives traffic from a small number of unique external IPs. While many environments use ADB for management, the presence of external connections followed by the aforementioned process and file artifacts indicates a successful compromise.

### What the Hunt Cannot See

This hunt relies on standard endpoint and network telemetry. A primary blind spot is the use of Unix domain sockets for mutex control. Kimwolf v7 uses a socket named '@n*boxv7' to ensure only one instance of the botnet is running; this is generally invisible to standard process snapshots and requires specialized socket logging. Additionally, since the attackers use residential proxies, we cannot inherently distinguish these connections from legitimate remote management without external IP reputation data.

### Deployment

This hunt is provided as a `hunt.md` playbook. This format allows for direct import into Huntbase or any other `hunt.md`-aware runtime. It is designed to be an iterative process: if 'netd_service' is found to be a legitimate component of a specific vendor's firmware, that vendor can be added to the exclusions for the next run.
