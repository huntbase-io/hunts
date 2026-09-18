# Hunting SPIFFE Identity Misuse and Workload Impersonation in Kubernetes

### Why Now
This hunt was developed in response to research by Unit 42 titled [The Machine With Many Faces: Post-Exploitation Identity Misuse in SPIFFE/SPIRE](https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/). The research demonstrates how an attacker with root access on a Kubernetes node can spoof cgroup and mount information to deceive a local SPIRE agent. By doing so, the attacker can obtain valid SVIDs (SPIFFE Verifiable Identity Documents) for any workload scheduled on that node, effectively bypassing identity-based security controls within the service mesh.

### The Hypothesis
We hypothesize that an attacker who has achieved root access on a Kubernetes node is actively harvesting SVIDs to impersonate legitimate workloads. This allows for lateral movement where the attacker can authenticate to other services as if they were a trusted application. Because the attacker relies on manipulating the local SPIRE agent's workload attestation process, evidence exists in both the process metadata of the compromised host and the subsequent anomalous authentication patterns in the environment.

### How the Hunt Flows
The first phase focuses on scoping. We identify nodes within the fleet that are running the `spire-agent`. These are the specific points of interest where SVID harvesting via selector spoofing is technically possible. This reduces the noise by excluding hosts that do not participate in the SPIFFE identity mesh.

Once the scope is defined, the hunt moves into parallel evidence gathering. We analyze authentication telemetry from `hb_auth_signin` to find SPIFFE identities appearing from unexpected or rare source IPs. This looks for identities that have 'travelled' away from their assigned pods. Simultaneously, we inspect `hb_process_activity` for root-level processes that are enumerating `/proc/` metadata, specifically targeting `cgroup` and `mountinfo` files. While some administrative tools do this, it is a high-signal behavior when correlated with workload nodes.

In the final phase, an automated triage agent correlates these signals. We look for the overlap: nodes where root processes were poking at container metadata and the corresponding SPIFFE IDs that showed up in anomalous sign-in events. This correlation helps distinguish between legitimate system maintenance and active identity misuse.

### What the Hunt Cannot See
There are two primary blind spots in this design. First, if an attacker uses a short-lived tool to harvest credentials that executes and terminates between EDR snapshots, the activity may not appear in `hb_process_activity`. Second, this hunt relies on normalized authentication events. If the stolen SVID is used for an mTLS connection at the transport layer that is not logged as a discrete sign-in event, we will miss the usage of the identity.

### How to Run This Hunt
This hunt is published as a `hunt.md` playbook. It is designed to be imported into Huntbase or any security runtime that supports the hunt.md specification. This format allows for the seamless transition between structured data queries and automated triage logic, making it possible to sweep a large Kubernetes fleet for identity-based lateral movement without manual query construction for every node.
