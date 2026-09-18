# Hunting for Suspicious Native Utility File Ingress in Cloud Workloads

### Why Now

Detecting ingress tool transfer via native utilities like `curl` and `wget` is notoriously noisy. In modern cloud environments, automation scripts and administrative tasks use these tools constantly, making traditional detection rules impractical for many teams. We were inspired by the recent discussion from [Elastic Security Labs](https://www.elastic.co/security-labs/blog/esql-completion-curl-wget-detection-triage) on using ES|QL to triage these alerts. This hunt takes that concept further by structuring a multi-stage investigation that moves from raw process execution to network-level corroboration.

### The Hypothesis

We hypothesize that an adversary is using standard utilities to download malicious payloads from infrastructure outside the known-good cloud ecosystem. By leveraging the same tools used for legitimate automation, they attempt to evade detection. However, their infrastructure will typically appear in the "long tail" of network activity—contacting destination IPs or domains that are not part of your standard mirrors, package repositories, or cloud service providers.

### How the Hunt Flows

The hunt begins by scoping activity to Linux and macOS hosts, where these utilities are most prevalent. It captures all command-line executions of `curl` and `wget` that contain literal URLs. This initial collection is deliberately broad, as the goal is to capture the full context of ingress before filtering begins.

Once the executions are identified, the hunt pivots to a parallel triage phase. It examines network connection logs to stack-count destination IPs, looking for those that appear on fewer than five hosts across the estate. Simultaneously, it correlates DNS activity against a baseline of known-good domains (like Microsoft, Amazon, or Elastic mirrors). This dual-layered approach allows us to isolate external, non-standard destinations that demand closer inspection.

In the final phase, an automated triage agent weighs the evidence. It evaluates the command line, the rarity of the destination, and the parent process context. For instance, a `curl` execution originating from an interactive shell (like `bash` or `zsh`) or downloading to a writable path like `/tmp` is weighted more heavily than a background daemon updating a known package. This narrows the results down to high-confidence leads for an analyst to investigate.

### What the Hunt Cannot See

This hunt has specific limitations. First, if an adversary obfuscates the download URL or reconstructs it at runtime within a script, the initial process-level regex will miss the activity. Second, without advanced session tracking (like eBPF-based metadata), it is difficult to definitively prove whether a download was initiated by a manual shell session or a background process, as parent process names can be spoofed or ambiguous.

### How to Run the Hunt

This hunt is provided as an open `hunt.md` playbook. You can import it directly into Huntbase or any other `hunt.md`-aware runtime. It is designed to be run periodically—we suggest a 14-day lookback—to establish a baseline of what "normal" ingress looks like for your specific cloud environment before investigating the anomalies.
