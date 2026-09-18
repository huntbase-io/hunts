# Hunting for Lateral Movement and Exfiltration After Cross-Environment Pivots

### Background: The Modern Pivot

Adversaries increasingly exploit the visibility gaps between disparate environments, such as cloud control planes and on-premises infrastructure. Once an initial foothold is established, the next steps involve lateral movement and, eventually, data theft. This hunt was developed following insights from the Unit 42 article, [Inside the Modern SOC: Defending the Cross-Environment Pivot](https://unit42.paloaltonetworks.com/soc-cross-environment-pivot/), which highlights how attackers leverage these transitions to evade detection.

### The Hypothesis

We hypothesize that an adversary is moving between internal hosts that do not typically interact, specifically focusing on newly provisioned or first-seen assets. After establishing this internal path, the attacker exfiltrates data using either high-volume outbound network flows or anomalous DNS patterns to bypass standard traffic monitoring.

### How the Hunt Flows

The hunt begins with a scoping phase focused on newly provisioned endpoints. By isolating devices first seen within the last week, we narrow the investigation to assets that might represent a recently compromised cloud instance or a newly deployed jump box. This stage provides a focused dataset for the subsequent behavioral analysis.

Next, the hunt analyzes internal network connections to identify rare host-to-host interactions. We specifically look for source and destination IP pairs that have appeared fewer than ten times across the entire fleet during the lookback period. This helps identify the lateral movement phase of an attack where an adversary is probing or connecting to internal resources for the first time.

Following the identification of rare internal movement, the hunt runs parallel checks for exfiltration signals. It looks for high-entropy DNS lookups—characterized by long query strings or high query frequency—and volumetric outbound transfers exceeding 100MB. These two surfaces provide a view into how data might be leaving the environment, whether through covert channels or direct egress.

Finally, the results are triaged by weighing the intersection of these behaviors. A host showing both a rare internal connection and an outbound data spike is treated as high risk. This multi-layered approach is why this is a hunt rather than a simple detection; single-point alerts for high data volume often result in noise, but the correlation of host age, internal rarity, and egress volume reveals the actual attack path.

### Blind Spots and Limitations

This hunt relies on EDR and network telemetry from managed endpoints. If an adversary moves through unmanaged assets—such as IoT devices or unauthorized servers without EDR—the visibility chain will break. Additionally, while the hunt monitors for volumetric exfiltration, it cannot inspect the content of TLS-encrypted traffic. Data sent to legitimate cloud storage providers via HTTPS may appear as normal volume unless combined with other indicators of compromise.

### How to Run This Hunt

This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any other `hunt.md`-aware runtime. It uses standard SQL-based queries against device, network, and DNS surfaces. Before running, ensure your telemetry lookback is sufficient to establish a baseline for rare connection patterns.

Source: Unit 42 — Inside the Modern SOC: Defending the Cross-Environment Pivot
