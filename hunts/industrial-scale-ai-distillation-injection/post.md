# Hunting Industrial-Scale AI Model Distillation and Prompt Injection Campaigns

The theft of intellectual property in the AI sector has moved beyond traditional file exfiltration to the extraction of model logic itself. A recent CISA advisory, [China-Based AI Companies Conducting Industrial-Scale Distillation Campaigns](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-251a), describes how adversaries use coordinated API requests to conduct 'distillation'—a process where a smaller model is trained on the outputs of a frontier model to replicate its capabilities. We have designed a hunt to identify the infrastructure and behavioral patterns associated with these extraction campaigns.

### The Hypothesis
We hypothesize that an adversary is conducting large-scale knowledge distillation by submitting coordinated prompt injections and high-entropy reasoning requests. These requests likely originate from API proxies or 'transfer stations' designed to bypass rate limits and geographic restrictions, aiming to extract chain-of-thought (CoT) reasoning and model weights via massive token exfiltration.

### How the Hunt Flows
The hunt begins with a scoping phase focused on the HTTP surface. We specifically look for source IPs or endpoints with anomalous request volumes hitting API completion endpoints. By identifying the top talkers by request count and outbound byte volume over a 14-day window, we can isolate infrastructure that suggests industrial-scale throughput rather than individual user behavior.

Once high-volume endpoints are identified, the hunt pivots into parallel corroboration across three surfaces. We search for adversarial prompt keywords in HTTP metadata (such as 'jailbreak' or 'thought') and identify User-Agents associated with known distillation entities like DeepSeek or MiniMax. Simultaneously, we examine DNS logs for lookups to suspected transfer station domains such as z.ai and proxy.z.ai, which are frequently used to tunnel these requests.

In the final telemetry phase, we stack-count outbound network flows to identify sustained, high-throughput connections. We specifically look for massive byte-to-packet ratios that indicate the automated extraction of large reasoning traces. A triage agent then correlates these independent signals—infrastructure markers, high-volume flow, and keyword hits—to determine if the activity represents legitimate heavy usage or a coordinated distillation campaign.

### What the Hunt Cannot See
This hunt has two primary blind spots. First, without deep packet inspection or full HTTP request body logging, we cannot see the specific contents of the prompts. Sophisticated injections hidden in POST bodies may be missed if they do not leave traces in the URL or headers. Second, the use of heavily obfuscated or multi-hop commercial proxies can hide the true origin of the traffic, making it difficult to attribute the activity to a specific geographic actor or entity beyond the immediate proxy IP.

### How to Run the Hunt
This hunt is provided as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime environment that supports the hunt.md standard. By running this as a hunt rather than a static detection, you can baseline normal API usage in your environment and identify the multi-stage infrastructure patterns that single-rule detections often overlook.
