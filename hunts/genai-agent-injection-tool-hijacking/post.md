# Hunting for GenAI Prompt Injection and Tool Hijacking in AWS

### Why this hunt

Elastic Security Labs recently detailed how System 1 models detect prompt injection in [Thinking fast about prompt injection: New System 1 models in Elastic](https://www.elastic.co/security-labs/blog/prompt-injection-detection-ai-agents). As organizations grant GenAI agents autonomy to call tools and access databases, prompt injection becomes more than a chat novelty; it becomes a vector for unauthorized tool execution and data exfiltration. This hunt moves beyond simple string matching to identify when an injection successfully hijacks an agent's behavior.

### The Hypothesis

An adversary manipulates GenAI agent behavior through natural language prompt injection or encoded payloads to bypass guardrails and execute unauthorized tool calls or API operations.

### How the Hunt Flows

The first query lists every AWS Bedrock agent in the environment. This establishes the attack surface by identifying foundation models, account IDs, and agent statuses. By identifying which agents are active, an analyst focuses the search on high-value targets.

Next, two queries run simultaneously to find evidence of prompt manipulation in cloud API activity. The first scans logs for common injection strings like "ignore all instructions" or "developer mode". The second looks for specific encoded payloads and known hashes mentioned in the Elastic report, such as Base64-encoded instruction overrides.

After these searches, an analyst or an automated agent weighs the early signals. They determine if the observed strings show intentional instruction overrides or evasion attempts through encoding. This triage step narrows the focus to credible injection attempts.

The hunt then pivots to behavioral anomalies. A query calculates a baseline of tool usage per actor and identifies users exceeding 50 tool-related API calls. Large batches of tool requests from a single user often indicate automated or hijacked activity rather than standard human interaction.

Finally, a correlation phase links the injection verdicts with the tool volume spikes. This confirms if an injection was successful and led to actual tool misuse. If both signals align for a specific actor, the hunt routes to containment actions like revoking IAM credentials.

### Blind Spots

CloudTrail Data Event Latency limits this hunt. If Data Events are not enabled for Bedrock, the `request_attribute` field may be truncated or missing, hiding the injection string from the logs. Additionally, AWS CloudTrail does not log the model's response body. The hunt cannot see if the agent refused the request, which is a key signal for identifying blocked but persistent exploit attempts.

### How to Run It

This hunt is an open `hunt.md` playbook. It imports directly into Huntbase or any compatible `hunt.md` runtime. Analysts can adjust the lookback period and specify IAM principals to narrow the scope during active investigations.
