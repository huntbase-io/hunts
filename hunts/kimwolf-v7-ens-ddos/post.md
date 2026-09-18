# Hunting for Kimwolf v7 ENS Resolution and IoT DDoS Activity

The evolution of the Kimwolf (AISURU) botnet, as detailed in the Unit 42 article [Kimwolf v7: An Evolution of the Kimwolf Botnet](https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/), highlights a significant shift toward infrastructure resilience. By moving C2 resolution to the Ethereum blockchain via the ENS protocol and using public RPC endpoints, the botnet avoids traditional domain takedowns. This hunt is designed to identify these behaviors on Linux and Android-based IoT assets where such activity is highly anomalous.

### The Hypothesis
An intruder is utilizing Ethereum ENS domains for C2 resolution and coordinating outbound DDoS attacks from compromised IoT or Android devices. We suspect this activity manifests as DNS lookups to public Ethereum RPC providers, followed by internal proxy relay behavior on a hard-coded port (23075) and high-volume outbound network traffic to known target clusters.

### How the Hunt Flows
The hunt begins by establishing the scope. We first inventory Linux and Android platforms within the environment. While standard workstations might legitimately contact Ethereum nodes for development purposes, an IoT device or Android TV box doing so represents a high-fidelity indicator of potential compromise.

Once scoped, the hunt parallelizes three checks. On the DNS surface, we look for queries to a known list of Ethereum RPC domains (like 0xrpc.io or eth.llamarpc.com) that the malware abuses to resolve its .eth C2 domains. Simultaneously, on the network surface, we look for traffic on port 23075. Kimwolf uses a local proxy relay on this port to coordinate its communications, making it a specific behavioral marker.

The final phase examines outbound network volume. We stack-count connections to identified target IP addresses associated with known Kimwolf DDoS campaigns. If a host shows combined indicators—blockchain resolution, proxy usage, and outbound volume—it is triaged for isolation.

### What the Hunt Cannot See
There are inherent blind spots in this design. Since Kimwolf uses Tor for some communications, and Tor traffic is encrypted and often uses randomized entry guards, we cannot easily see the content of the .onion C2 traffic through simple network metadata. Additionally, while the research mentions specific Chrome fingerprints in HTTP/2 traffic, many IoT telemetry agents do not provide the deep packet inspection or library-load data necessary to confirm these fingerprints.

### Running the Hunt
This hunt is provided as a `hunt.md` playbook. It is designed to be imported into Huntbase or any other `hunt.md`-aware runtime. Because this requires pivoting between three independent telemetry surfaces—DNS, local network listeners, and outbound traffic volume—it is structured as a hunt rather than a single detection rule. This approach allows for weighing multiple signals to provide high-confidence triage on assets that are often difficult to monitor.
