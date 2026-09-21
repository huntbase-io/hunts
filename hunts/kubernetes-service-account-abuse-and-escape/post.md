# Hunting Kubernetes Service Account Abuse and Container Escape

### Why this hunt
Elastic Security Labs published a deep dive titled How to correlate Kubernetes audit logs with container runtime data (https://www.elastic.co/security-labs/threat-command/kubernetes-audit-logs-container-escape). The research highlights the difficulty of tracking an adversary as they move from a single container to the underlying host. We designed this hunt to bridge that gap by connecting runtime process events with the Kubernetes control plane.

### The Hypothesis
An intruder harvests a service account token from a compromised pod. They use this token to authenticate with the Kubernetes API and deploy a privileged pod. This new pod uses host namespaces or mounts the host filesystem to facilitate a container escape, bypassing process-only detections that do not see the API-level interaction.

### How the Hunt Flows
The first phase focuses on scoping and identifying the environment. We use the hb_software_inventory surface to find hosts running Kubernetes components like kubelet, docker, or containerd. This step ensures the hunt only runs on relevant infrastructure and reduces the processing load on unrelated systems.

Once we identify the targets, we look for evidence of discovery and harvesting. One branch of the hunt queries hb_process_activity for rare executions of tools like kubectl, kube-hunter, or kube-bench. We specifically look for manual commands like getting pods or secrets. At the same time, we check hb_file_activity for any process reading the service account token from the standard secret path.

The triage phase then links these two activities. An analyst looks for the same host or process context where discovery tools were run and tokens were accessed. This connection suggests a purposeful attempt to gather credentials for a lateral move toward the cluster API.

The next phase examines the Kubernetes control plane. We query the kubernetes_pod surface for pods configured with host_pid, host_network, or host_ipc set to true. These settings are the hallmarks of a container escape attempt. By correlating the timing of these deployments with the earlier token harvesting, the hunt confirms the intent and impact of the attack.

The final assessment weighs the early-stage discovery findings against the appearance of these privileged pods. Does the timing and identity suggest the discovery led directly to this deployment? An analyst confirms the verdict and initiates isolation if the attack chain is complete.

### Blind Spots and Limitations
This hunt has two primary blind spots. First, it cannot see the specific commands executed via kubectl exec because that data resides in Kubernetes Audit Logs, which are not currently part of the queried hb_ surfaces. Second, the hunt relies on periodic snapshots of the pod inventory. If an adversary deploys an ephemeral privileged pod that only exists for a few seconds to perform an escape, the inventory might miss it.

### Running the Hunt
This hunt is an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. It provides the necessary queries and logic to automate the correlation between endpoint telemetry and container orchestration layers.
