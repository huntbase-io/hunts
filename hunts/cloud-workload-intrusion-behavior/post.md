# Hunting for Runtime Intrusion Patterns in Cloud Workloads

### Why Now
As emphasized in the latest industry evaluations like [Microsoft named a Leader in the Frost Radar™: Cloud Workload Protection Platforms, 2026](https://www.microsoft.com/en-us/security/blog/2026/08/19/microsoft-named-a-leader-in-the-frost-radar-cloud-workload-protection-platforms-2026/), the focus for cloud security has shifted from static configuration auditing to runtime protection. Vulnerability scanning alone is insufficient; teams need to know when a known vulnerability moves from a potential risk to an active exploitation event.

### The Hypothesis
This hunt is built on the premise that an adversary has exploited a public-facing application or container vulnerability to gain initial access. Following this access, they will likely execute suspicious processes (such as shells or network utilities) and attempt to establish outbound command-and-control (C2) communication via anomalous DNS lookups. We also look for binary drift—unauthorized modifications or deletions of files within sensitive container directories.

### How the Hunt Flows
The first phase focuses on scoping. We identify assets that are both internet-exposed and contain high-severity vulnerabilities. This narrows the investigation from the entire estate to the high-risk 'front door' of the production environment, ensuring we spend cycles where exploitation is most probable.

Next, the hunt moves into a parallel runtime investigation. We pivot into process activity, specifically looking for shells (bash, sh) and network tools (curl, nc) running from paths associated with container runtimes like Docker or containerd. At the same time, we look for binary drift by monitoring for file modifications or deletions in /bin and /usr/local/bin within those same container paths.

The final technical phase baselines DNS activity. We filter out the standard infrastructure queries and look for rare outbound connections originating specifically from container-resident processes. This helps identify potential data exfiltration or C2 traffic that lacks the volume of standard production traffic.

Finally, we perform triage. This involves correlating the findings from the previous steps. A host that is both vulnerable and showing a combination of shell execution, binary drift, and rare DNS lookups is flagged for immediate isolation. This multi-plane correlation is why this is a hunt rather than a single detection rule, as individual signals like a shell spawn can often be benign in development or CI/CD contexts.

### What This Hunt Cannot See
There are two primary blind spots to consider. First, if container nodes lack eBPF-based runtime monitoring, the hunt will miss unauthorized code execution that does not report to the central collector. Second, attackers using TLS-encrypted C2 or domain fronting may evade the DNS prevalence checks, as this hunt does not perform deep packet inspection of outbound traffic.

### How to Run It
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any other runtime that supports the hunt.md standard. It is designed to be run periodically against production clusters (AKS, EKS, GKE) to verify the absence of post-exploitation behavior on your most vulnerable assets.
