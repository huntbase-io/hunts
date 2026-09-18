# Detecting Industrial-Scale AI Model Distillation via API Transfer Stations

In a recent joint advisory, [CISA Advisory AA26-251A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-251a) detailed how China-based AI companies are conducting industrial-scale distillation campaigns. These actors are not just abusing APIs; they are systematically extracting proprietary model capabilities to train their own competitive models. This process involves the use of 'transfer station' proxies and massive fleets of fraudulent accounts to bypass rate limits and geographic restrictions. We have published a new hunt design to help practitioners identify this activity within their API infrastructure.

### The Hypothesis
The hunt operates on the hypothesis that actors are using fraudulent account clusters and specialized proxies to conduct high-volume extraction. Because individual accounts may stay just below detection thresholds, we focus on the aggregation points. We expect to see dozens or hundreds of unique accounts originating from a single source IP, resolving specific distillation-focused domains, and exhibiting uniform automation fingerprints across those accounts.

### How the Hunt Flows
The hunt begins with a scoping phase focused on the identity layer. We examine sign-in logs to identify 'transfer stations'—source IPs hosting an abnormal density of unique user accounts. By setting a threshold for unique actors per IP, we can isolate infrastructure that likely represents a proxy or an automated bot fleet rather than legitimate enterprise egress.

Once the suspicious infrastructure is identified, the hunt pivots into parallel enrichment and verification steps. We correlate these source IPs with DNS activity to see if the gateways are resolving known distillation proxies like z.ai or other transfer station domains. Simultaneously, we measure the sheer volume of request throughput and response bytes. Legitimate users may make thousands of requests, but industrial-scale distillation typically generates millions of requests over the same lookback period.

Finally, the hunt looks for behavioral consistency. We analyze User-Agent strings and other HTTP headers across the identified account clusters. In a coordinated campaign, these fingerprints are often uniform, indicating a scripted extraction process rather than diverse, human-driven traffic. This multi-surface correlation allows us to distinguish a systematic distillation campaign from noisy but legitimate bulk API usage.

### What the Hunt Cannot See
This design has two primary blind spots. First, it lacks visibility into the actual prompt text. Without HTTP request body logging, we cannot confirm if the prompts are using 'chain-of-thought' or 'jailbreak' techniques specifically designed for distillation; we are relying on volume and density as proxies for intent. Second, if the actor uses highly sophisticated IP rotation or residential proxy networks that change faster than the hunt cycle, the static identification of 'transfer stations' will be less effective.

### How to Run This Hunt
This hunt is provided as an open-source hunt.md playbook. It is designed to be imported into Huntbase or any other hunt.md-aware runtime. Because it utilizes common surfaces like authentication, DNS, and HTTP activity, it can be adapted to most centralized logging environments or SIEMs. Analysts should adjust the account density and request volume thresholds based on their own baseline of legitimate enterprise API consumers.
