# Hunting Kimwolf Botnet Propagation via Unauthenticated ADB Services

### Why this hunt?

Recent research by Unit 42 in "Kimwolf v7: An Evolution of the Kimwolf Botnet" (https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/) highlights how the Kimwolf botnet, also known as AISURU, has evolved to target Android-based IoT devices. These devices often expose the Android Debug Bridge (ADB) on port 5555 without authentication. This configuration provides an easy entry point for automated scanners to deploy malware and recruit the device into a DDoS swarm.

### The Hypothesis

An intruder exploits unauthenticated ADB services on port 5555 to drop ELF binaries and masquerades as the netd_service system process to avoid detection on Android IoT devices.

### How the Hunt Flows

The first phase scopes the environment for any host receiving inbound traffic on port 5555. An automated agent evaluates these leads by checking the source IP addresses. Traffic originating from external ranges or known residential proxies moves the hunt forward. Traffic from internal developer subnets is noted but deprioritized to reduce noise.

Once the hunt identifies high-risk hosts, it triggers a parallel forensic fan-out. One query searches for specific ELF binary drops like libdevice.so and kernel.so, particularly focusing on the /data/local/tmp directory or other writable paths. The hunt also checks for the libn%kernel.so naming pattern observed in recent v7 samples.

Simultaneously, a second query baselines the netd_service process. Because Kimwolf masquerades its botnet agent as this legitimate system service, the hunt looks for instances running from non-standard paths or appearing on only a few hosts across the estate. A legitimate netd_service usually runs from a consistent, system-owned path and appears globally across the device fleet.

The final phase triages these results. An agent correlates the initial network connection with the presence of suspicious files and the rare process execution. This sequence—unauthenticated access followed by binary drops and masquerading—confirms an infection and triggers an isolation action for the affected host.

### Blind Spots

The hunt relies on network telemetry for the initial lead. If a host is compromised via ADB but the connection occurs on a segment without flow logging, the hunt will miss the entry point. Additionally, many IoT devices are unmanaged and do not run an endpoint agent. This hunt only observes artifacts on devices where process and file auditing are active.

### How to Run It

This hunt is a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. It uses SQLite queries against your network and endpoint telemetry. You should prioritize running this against segments containing Android-based appliances, smart TVs, or industrial IoT controllers.
