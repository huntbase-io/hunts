# Hunting Industrial-Scale AI Model Distillation Infrastructure

### Why now

A recent advisory from CISA, [AA26-251A — China-Based AI Companies Conducting Industrial-Scale Distillation](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-251a), highlights a growing trend of adversaries utilizing 'transfer stations' to harvest intellectual property from U.S. AI companies. These actors use multi-hop proxies and API aggregators to mask their geographic origin and identity while submitting millions of prompts to distill proprietary model logic into their own systems.

### The Hypothesis

We hypothesize that an adversary conducting industrial-scale distillation will exhibit a specific footprint at the access and transport layers. They likely utilize shared infrastructure (IPs) to manage multiple user accounts and generate API request volumes that significantly exceed standard developer behavior, often while resolving DNS for known API-proxy or 'aggregator' domains.

### How the Hunt Flows

The hunt begins at the identity layer, specifically the `hb_auth_signin` surface. We look for 'account clustering'—single source IP addresses successfully authenticating into more than five distinct accounts within a two-week window. This is a common indicator of a shared proxy or a centralized collection hub used by a single entity to spread their request volume across multiple identities.

Next, the hunt moves into parallel corroboration across network and application surfaces. We look for industrial-scale throughput in `hb_http_activity`, specifically targeting common model endpoints like chat completions. Simultaneously, we inspect `hb_dns_activity` for queries related to known API aggregator domains and transfer stations. The goal is to see if the high-volume accounts identified in the first phase are the same ones utilizing these obfuscation services.

Finally, the hunt enters a triage phase. This is necessary because raw metadata alone cannot always distinguish a malicious distillation actor from a large, legitimate enterprise customer. This phase focuses on correlating the three signals—account sharing, request volume, and proxy usage—to reach a verdict before recommending any containment actions like session termination or IP blocking.

### What the Hunt Cannot See

This hunt has two primary blind spots. First, without access to full HTTP request bodies, we cannot inspect the prompts themselves. We rely on volume and infrastructure metadata; we cannot see if the prompts follow specific distillation templates like 'Chain of Thought' extraction. Second, if an adversary uses a high-rotation residential proxy network rather than fixed datacenter IPs, they may not trigger our account clustering thresholds.

### How to Run This Hunt

This hunt is packaged as an open `hunt.md` playbook. It can be imported directly into Huntbase or any security runtime that supports the hunt.md specification. It is designed to be run as a periodic assessment rather than a real-time detection, as the correlation between auth, DNS, and HTTP surfaces is most effective when analyzed over a multi-day lookback period.
