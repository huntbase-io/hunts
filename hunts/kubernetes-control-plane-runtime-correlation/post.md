# Correlating Kubernetes Audit Logs with Container Runtime Behavior

### Why Now
Monitoring Kubernetes environments requires looking at two distinct planes simultaneously: the API server (control plane) and the individual nodes (runtime plane). A recent technical deep dive by Elastic Security Labs, [How to correlate Kubernetes audit logs with container runtime data](https://www.elastic.co/security-labs/threat-command/kubernetes-audit-logs-container-escape), highlights the necessity of this correlation. Many container escapes rely on a combination of valid API credentials and low-level system tools, making it difficult to distinguish between a legitimate admin session and an adversary pivoting through the cluster.

### The Hypothesis
We hypothesize that an adversary who has compromised a containerized workload will seek to escalate privileges by accessing the Service Account (SA) token mounted within the pod. They will then use this token to interact with the Kubernetes API to gather intelligence or deploy privileged pods, eventually using tools like `nsenter` or `chroot` to escape the container boundary and reach the underlying node.

### How the Hunt Flows
The hunt begins with scoping, identifying hosts within the software inventory that are running `kubelet` or other Kubernetes components. This ensures we are only looking at relevant node infrastructure and reduces the volume of data processed in subsequent steps.

Next, the hunt focuses on the endpoint plane by looking for processes accessing Service Account tokens in standard paths like `/var/run/secrets/kubernetes.io/serviceaccount/token`. While many legitimate processes read these tokens, we look for rare binaries or interactive shells performing these reads to find initial leads.

We then look for the execution of container escape tools. By stack-counting the execution of `nsenter` and `chroot` across the fleet, we can isolate rare instances. Legitimate node maintenance often uses these tools across many hosts, whereas an escape attempt is typically localized to a single compromised pod.

Finally, the hunt pivots to the Kubernetes API plane by examining HTTP activity logs. We look for API requests involving pod execution, secret listing, or pod creation that coincide with the runtime behavior observed on the nodes. By joining the `device_hostname` from endpoint logs with the active pod inventory, we map process activity back to specific orchestrator resources for triage.

### Blind Spots
This hunt has two primary limitations. First, if Kubernetes Audit Logs are configured only at the 'Metadata' level, the requestURI or body containing specific 'exec' commands may not be visible in the HTTP logs. Second, endpoint file activity logs typically capture the 'open' call; if a long-running process already holds a handle to a Service Account token, its continued use will not trigger new file access events.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. This format allows the logic to be imported directly into Huntbase or any hunt-aware runtime environment. It is designed to be a hunt rather than a detection because the correlation of API traffic and process execution is necessary to filter out the administrative noise inherent in Kubernetes operations. 

Before running, ensure your logging infrastructure is capturing both HTTP traffic to the API server and file/process events from the nodes. Adjust the `lookback_days` parameter based on your environment's log retention.
