# Hunting for Agentic AI Resource Hijacking in Cloud Environments

The recent Unit 42 investigation, [An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation](https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/), highlights a shift in adversary behavior. Attackers are now using AI-assisted automation to compress the time between initial access and exploitation. Specifically, they are hijacking cloud AI credentials to power their own agentic loops. This hunt is designed to identify the footprint of these automated agents when they leverage stolen developer identities to interact with cloud AI providers.

### The Hypothesis
Our hypothesis is that an adversary has successfully hijacked cloud AI credentials and is running automated agentic loops from within or against the environment. This activity manifests as bursty authentication patterns, rapid transitions between unauthorized and successful states (flapping) as the agent manages tokens, and anomalous model invocation traffic originating from developer identities that do not typically exhibit such high-frequency behavior.

### How the Hunt Flows
The hunt begins by scoping the environment to systems most likely to host agentic orchestration. We use software inventory telemetry to identify hosts running Docker or containerized development environments. These nodes are the primary candidates for hosting the automated loops observed in recent AI-assisted campaigns.

Next, we pivot to identity telemetry to look for distributed cloud authentications. We examine successful sign-ins where a single identity appears across multiple distinct source IPs in a short window. This pattern often distinguishes a distributed automated agent from a human developer working from a known location.

In the network phase, we baseline HTTP activity against known AI model invocation endpoints like OpenAI, Bedrock, and Anthropic. We look for two specific signals: massive request volumes that deviate from the identity's historical baseline and authentication state transitions. Specifically, we look for identities that experience 401 unauthorized codes immediately followed by 200 successes on the same AI endpoint, suggesting automated credential testing or token refresh cycles.

Finally, the hunt correlates these signals. An identity that is both authenticating from multiple IPs and exhibiting flapping behavior on AI endpoints—specifically when linked to a Docker-enabled host—is a high-confidence candidate for resource hijacking.

### Blind Spots
This hunt relies heavily on outbound HTTP visibility. If your environment lacks HTTP telemetry (such as VPC flow logs or forward proxy logs) for known AI API endpoints, you will be unable to see the request volume or status code transitions. In such cases, the hunt must rely solely on authentication data, which may miss resource abuse if the adversary is using pre-existing, valid sessions.

### Why This is a Hunt, Not a Detection
While a single rule might catch a burst of 401 errors, it cannot differentiate between a misconfigured internal tool and a hijacked agent loop. This process requires a hunt because it correlates behavior across three distinct surfaces: container-based scoping, distributed identity anomalies, and bursty HTTP request baselining. Only by combining these signals can we confirm the agentic cycle of failure-to-success transitions combined with rare identity-host mappings.

### How to Run It
This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any hunt.md-aware runtime. By using the provided SQLite queries, you can automate the scoping and correlation phases across your identity and network telemetry layers.
