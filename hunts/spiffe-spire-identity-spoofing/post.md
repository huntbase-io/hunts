# Hunting for SPIFFE/SPIRE Workload Identity Spoofing

### Why this hunt

Recent research from Palo Alto Networks Unit 42, titled [The Machine With Many Faces: Post-Exploitation Identity Misuse in SPIFFE/SPIRE](https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/), details how an adversary with root access on a Kubernetes node can bypass workload identity boundaries. SPIFFE/SPIRE relies on selectors—often cgroup membership—to verify which pod is requesting an identity. If an attacker manipulates these selectors, they can trick the SPIRE agent into issuing certificates belonging to other pods on the same node. We designed this hunt to find the technical traces left by this metadata manipulation.

### The Hypothesis

An attacker with root access on a Kubernetes node spoofs cgroup metadata to trick the SPIRE agent into issuing identities belonging to co-located workloads for unauthorized service impersonation. This behavior bypasses the isolation intended by service mesh and identity-based security policies.

### How the Hunt Flows

The hunt begins by narrowing the scope to nodes running SPIRE agents. The first query searches software inventory for active agent packages to ensure the analyst focuses only on relevant infrastructure where identity spoofing is a viable threat.

Once scoped, the hunt monitors the SPIRE agent's Unix socket for access by interactive tools like shells or networking utilities. Standard workloads typically use automated libraries to communicate with the socket; a human operator or a generic script using tools like curl or socat to fetch SVIDs is a high-confidence indicator of tampering.

Simultaneously, the hunt looks for rare process activity involving Kubernetes cgroup slices. The adversary must reference specific paths like kubepods.slice in command lines or use specialized research tools like 'spooffe' to execute the attack. This phase baselines normal pod behavior and highlights anomalies where non-agent processes touch internal cgroup metadata.

In the final phase, an analyst correlates these findings with network telemetry. The hunt identifies mTLS-related traffic originating from the same suspicious processes. Confirming that a process which tampered with the agent socket later initiated outbound service-to-service connections provides the evidence needed to confirm successful impersonation.

### Blind Spots and Limitations

This hunt relies on process and file telemetry. If an attacker uses kernel-level rootkits or direct syscalls to spoof cgroup information without spawning a shell or using identifiable tools, the activity may stay below the threshold of command-line logging. Additionally, the actual harvesting of SVIDs occurs in the SPIRE agent's memory. Without specific agent-level logging that records the calling PID for every FetchSVID request, the hunt cannot observe the moment the credential passes from the agent to the attacker.

### How to Run This Hunt

You can run this playbook as a hunt.md file. It imports directly into Huntbase or any runtime compatible with the hunt.md specification. The playbook includes the required KQL or SQL queries to surface the data and provides logic for an automated agent to triage the results. Because this hunt correlates activity across process, file, and network surfaces, it functions as a comprehensive investigation rather than a simple detection rule.
