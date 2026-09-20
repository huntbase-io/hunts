# Hunting AI-Agentic Privilege Escalation and Infrastructure Hijacking

### Why Now

Our team developed this hunt following the recent Unit 42 investigation, "An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation" (https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/). The report highlights how adversaries now use agentic AI to automate complex tasks like privilege escalation and infrastructure exploitation, turning what was once a week-long effort into an afternoon of activity.

### The Hypothesis

An automated AI agent loop conducts high-speed privilege escalation via secrets managers, tampers with CI/CD configurations, and hijacks cloud AI endpoints for external orchestration. This loop allows the intruder to adapt to failures in real-time, rapidly rotating through credentials and scripts to find a path to the core environment.

### How the Hunt Flows

The hunt begins with a scoping phase using the hb_software_inventory surface. We look for hosts running Docker or other containerization software, as these environments often host the web services used as initial entry points and tunneling hubs.

Next, we execute three parallel checks to find evidence of the agentic loop. The first query monitors the hb_http_activity surface for rapid authentication state shifts. We specifically look for source IPs or user identities that experience multiple 401 Unauthorized errors followed by a 200 OK success on sensitive API endpoints within a 15-minute window. This pattern indicates an automated tool cycling through secrets or brute-forcing access.

Simultaneously, we pivot to the hb_file_activity surface to detect tampering with DevOps configurations. The hunt searches for modifications to Terraform files or CI/CD workflow directories. Agents often target these files to plant backdoors or exfiltrate environment variables, and doing so in coordination with an authentication shift provides strong evidence of an active intrusion.

Finally, the hunt baselines AI provider traffic. We monitor connections to endpoints like OpenAI, Anthropic, and AWS Bedrock. A sudden burst of traffic to these services from an internal host, especially one involved in the previous phases, suggests the adversary is hijacking your own AI infrastructure to orchestrate the next stage of their attack.

### What the Hunt Cannot See

This hunt has two primary blind spots. First, we lack visibility into the specific payloads or prompts sent to AI endpoints. While we can see the volume of traffic, we cannot distinguish between a malicious agent's instructions and legitimate development activity without deep packet inspection. Second, if the agent executes scripts entirely in the memory of ephemeral CI/CD runners, our file system queries may miss the activity if those runners lack persistent monitoring agents.

### How to Run This Hunt

This hunt is packaged as an open hunt.md playbook. It imports directly into Huntbase or any other hunt.md-aware runtime. It uses standard surfaces for HTTP, file, and inventory telemetry, making it portable across environments that provide these data streams.
