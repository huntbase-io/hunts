# Hunting for Compromised AI Runtimes and Outbound Tunnels

### Why Now

Rapid7 recently published [Open by Default, Already Occupied: Threat Actors are Renting your Compute](https://www.rapid7.com/blog/post/tr-self-hosted-ai-renting-compute-exposed-servers), detailing how adversaries exploit unauthenticated AI runtimes. Thousands of instances of Ollama and Jupyter are currently exposed to the internet without a password. Attackers do not just want the data; they want the compute. They use these systems to run their own models or establish persistent outbound tunnels to bypass firewalls.

### The Hypothesis

An adversary identifies unauthenticated AI runtimes exposed to the internet and uses them to verify connectivity or establish command-and-control via outbound tunneling services. By targeting services like Ollama (port 11434) or Jupyter (port 8888), they gain a high-performance beachhead in the corporate environment.

### How the Hunt Flows

The hunt begins with a scoping phase on the `hb_exposed_assets` surface. It identifies internal hosts that external scanners have already flagged as exposing AI runtimes. This focuses the investigation on the most likely entry points rather than searching every host in the estate.

Once the hunt identifies exposed hosts, it pivots to behavioral telemetry. The workflow runs two queries in parallel. The first checks the `hb_dns_activity` surface for resolutions of free tunneling domains like bore.pub or trycloudflare.com. These services are commonly used by attackers to create a stable callback from an unauthenticated server. The second query monitors the `hb_http_activity` surface for probes against sensitive API paths, such as `/api/pull` or `/api/tags`, coming from external IP addresses.

Finally, an analyst or agent triage weighs these signals. A host that appears in the external exposure list and also initiates outbound tunnel DNS lookups suggests a successful compromise. This correlation allows the team to distinguish between a service that is merely misconfigured and one that is actively being used as an adversary's remote terminal.

### What the Hunt Cannot See

This hunt has two primary blind spots. First, it cannot inspect the full HTTP request body in many standard proxy logs. An attacker might use a POST request to `/api/pull` containing a path-traversal payload; while we see the request to the endpoint, we may not see the specific malicious manifest digest. Second, unmanaged VPS hosts often lack process-to-network mapping. Without this, we cannot definitively prove the Ollama process initiated the DNS resolution rather than a legitimate developer tool.

### How to Run This Hunt

This hunt is provided as a `hunt.md` playbook. It is designed to be machine-readable and imports directly into Huntbase or any runtime that supports the hunt.md specification. Running it periodically helps verify that your 'expensed' cloud servers remain under your control and have not been repurposed by external actors.
