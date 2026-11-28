---
analysis: A simple rule can fire on the string 'ignore all instructions', but this
  hunt pivots to behavioral tool-invocation spikes and uses an agent to correlate
  the natural language intent with the outcome, reducing noise from testing and development.
blind_spots:
- id: cloudtrail-data-event-latency
  question: whether model invocation bodies are logged in full
  requires: CloudTrail Data Events enabled for Bedrock
  risk: If Data Events are not enabled or only Management Events are captured, the
    prompt content (request_attribute) may be truncated or missing, hiding the injection
    string.
  stage: initial-access-prompt-injection
- id: no-response-body-logging
  question: whether the model refused the request due to a guardrail firing
  requires: Indexing of gen_ai.output.messages
  risk: Without visibility into the assistant's response body, we cannot see the 'refusal'
    signal, which is a key indicator of a blocked but attempted exploit.
  stage: impact-model-refusal
coverage:
- stage: initial-access-prompt-injection
  status: covered
  steps:
  - detect-injection-strings
- stage: defense-evasion-encoded-payloads
  status: covered
  steps:
  - detect-encoded-payloads
- stage: execution-agent-tool-misuse
  status: covered
  steps:
  - detect-tool-volume-spikes
- blind_spot: no-response-body-logging
  reason: AWS CloudTrail does not log the model response body by default; needs specialized
    LLM telemetry integration.
  stage: impact-model-refusal
  status: not_visible
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: As GenAI agents are granted autonomous permissions to call tools
    and access databases, protecting them from prompt injection is critical to preventing
    unauthorized goal hijacking and data theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is manipulating GenAI agent behavior through natural language
  prompt injection or encoded payloads to bypass guardrails and execute unauthorized
  tool calls or API operations.
labels:
- hunt
- attack.t1190
- attack.t0034
- attack.t0051
- attack.t0053
- attack.t0054
- defense evasion
- execution
- impact
- initial access
- aws
name: GenAI Agent Prompt Injection and Tool Hijacking
parameters:
  base64_payload:
    default: SWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnMu
    description: Specific Base64 payload from the report (Ignore all previous instructions).
    from:
      kind: article
      observed: '2026-11-23'
      ref: https://www.elastic.co/security-labs/blog/prompt-injection-detection-ai-agents
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  md5_ioc:
    default: 5f4dcc3b5aa765d61d8327deb882cf99
    description: The MD5 hash of 'password' as a sample credential leak/payload string.
    from:
      kind: article
      observed: '2026-11-23'
      ref: https://www.elastic.co/security-labs/blog/prompt-injection-detection-ai-agents
    type: string
  scope_hosts:
    default: []
    description: Specific IAM principals or hostnames to scope the hunt to; leave
      empty for all.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/prompt-injection-detection-ai-agents
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on high-privilege IAM roles and identities that interact with AWS
  Bedrock. Widen scope if injection strings appear from normally benign user accounts.
references:
- name: 'Thinking fast about prompt injection: New System 1 models in Elastic'
  url: https://www.elastic.co/security-labs/blog/prompt-injection-detection-ai-agents
related:
- hunt: genai-cost-harvesting-detection
  reason: Large scale cost-harvesting through model abuse is a sibling threat but
    requires specific monitoring of token consumption rather than prompt injection.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: GenAI Prompt Injection
    observables:
    - Ignore all previous instructions
    - Instruction overrides in gen_ai.input.messages
    - Natural language injection attempts
    slug: initial-access-prompt-injection
    tactic: initial-access
    techniques:
    - T1190
    - T0051
  - name: Encoded and Obfuscated Payloads
    observables:
    - SWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnMu
    - 5f4dcc3b5aa765d61d8327deb882cf99
    - Leetspeak
    - Morse code
    - 0xNN hex strings
    - Decorative Unicode
    slug: defense-evasion-encoded-payloads
    tactic: defense-evasion
    techniques:
    - T0054
  - name: Anomalous Agent Tool Invocation
    observables:
    - Unusually large tool-request batches
    - Rare tool selection per user.id
    - High tool-call volume
    - Bedrock invocation spikes
    slug: execution-agent-tool-misuse
    tactic: execution
    techniques:
    - T0053
    - T0034
  - name: GenAI Assistant Refusal
    observables:
    - Refusal text in gen_ai.output.messages
    - Assistant refusals indicating guardrail firing
    slug: impact-model-refusal
    tactic: impact
    techniques:
    - T0054
  summary: Threat actors target GenAI agents using prompt injection to override system
    instructions and execute unauthorized tool calls or hide malicious payloads within
    encoded strings. The campaign is characterized by the use of natural language
    to bypass traditional filters, employing Base64 encoding, leetspeak obfuscation,
    and high-volume tool invocation to exploit agentic capabilities.
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  aws:
    category: siem
    huntbase:
      product: aws
    name: aws
  endpoint:
    category: endpoint
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# GenAI Agent Prompt Injection and Tool Hijacking

This hunt identifies attempts to hijack GenAI agents, specifically targeting AWS Bedrock. It correlates early-stage natural language injection attempts and encoded payloads with follow-on behavioral anomalies, such as unusually high tool invocation volume. The hunt uses a phased approach: first identifying vulnerable agents and injection attempts, then corroborating these with actual execution patterns across cloud API logs.

## identify-bedrock-agents
<!-- Identify AWS Bedrock agents -->
Find the foundation models and agents currently configured in the environment to establish scope.

```sqlite target=aws role=scoping
~~~yaml
expected: A list of agents that could be targets for injection. Silence means no Bedrock
  agents are configured.
reads:
- arn
- agent_name
- foundation_model
- agent_status
- account_id
silence: not_evidence_of_absence
source: aws_bedrock_agent
verified: dry-run
verified_at: '2026-11-24'
~~~
SELECT arn, agent_name, foundation_model, agent_status, account_id FROM aws_bedrock_agent
```

## early-injection-indicators
<!-- Parallel search for injection indicators -->
parallel:
- → detect-injection-strings
- → detect-encoded-payloads
join: → weigh-early-signals

## detect-injection-strings
<!-- Detect prompt injection strings -->
Identify natural language strings used to override agent instructions in API calls.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A row indicates an explicit prompt injection attempt. Silence means no common
  override strings were found in the logged request attributes.
reads:
- time
- actor_user_name
- request_attribute
- api_operation
- cloud_account_uid
- api_service_name
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-24'
~~~
SELECT time, actor_user_name, request_attribute, api_operation, cloud_account_uid FROM hb_cloud_api_activity WHERE LOWER(api_service_name) LIKE '%bedrock%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || actor_user_name || ',') > 0) AND (LOWER(request_attribute) LIKE '%ignore all%' OR LOWER(request_attribute) LIKE '%instruction override%' OR LOWER(request_attribute) LIKE '%developer mode%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## detect-encoded-payloads
<!-- Detect encoded payloads and hashes -->
Search for obfuscated content or hash strings used to bypass simple text filters.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, base64_payload=base64_payload, md5_ioc=md5_ioc)
~~~yaml
expected: Specific indicators from the report appearing in Bedrock API traffic.
reads:
- time
- actor_user_name
- request_attribute
- api_operation
- api_service_name
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-24'
~~~
SELECT time, actor_user_name, request_attribute, api_operation FROM hb_cloud_api_activity WHERE LOWER(api_service_name) LIKE '%bedrock%' AND (instr(request_attribute, '{{base64_payload}}') > 0 OR instr(request_attribute, '{{md5_ioc}}') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## weigh-early-signals
<!-- Weigh early-stage injection signals -->
```agent target=hunter
cite: required
context:
- detect-injection-strings
- detect-encoded-payloads
max_iterations: 3
objective: Determine if the prompts observed in the parallel steps show intentional
  instruction overrides or evasion through encoding.
success_criteria: A list of actors or accounts that attempted prompt injection.
tools:
- aws
- endpoint
```

## detect-tool-volume-spikes
<!-- Detect anomalous tool invocation volume -->
Corroborate injection attempts with subsequent behavioral anomalies in tool usage.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: prior_equal_window
  window: '{{lookback_days}}d'
expected: A high-volume tool-request batch from a single user. Silence proves the
  absence of large automated tool misuse within the lookback.
prevalence:
  by: actor_user_name
  key:
  - api_operation
  rare_below: 5
reads:
- actor_user_name
- api_operation
- time
- api_service_name
silence: evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-24'
~~~
SELECT actor_user_name, api_operation, COUNT(*) as call_count, MIN(time) as first_call, MAX(time) as last_call FROM hb_cloud_api_activity WHERE LOWER(api_service_name) LIKE '%bedrock%' AND (LOWER(api_operation) LIKE '%invoke%' OR LOWER(api_operation) LIKE '%call%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, api_operation HAVING call_count > 50 ORDER BY call_count DESC
```

## final-correlation-read
<!-- Final correlation read -->
```agent target=hunter
cite: required
context:
- weigh-early-signals
- detect-tool-volume-spikes
max_iterations: 3
objective: Correlate the injection verdicts from the first agent with the tool volume
  anomalies to confirm if an injection was successful and led to unauthorized actions.
success_criteria: A per-actor verdict of malicious hijacking or benign use.
tools:
- aws
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The final correlation read confirms an injection attempt followed by anomalous tool usage for at least one actor." (confidence: high, judge=hunter)
then: → revoke-iam-access
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: cloudtrail-data-event-latency)
else: → close-out

## revoke-iam-access
<!-- Revoke IAM access -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke active IAM sessions and temporary credentials for the identified actor_user_name.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Examine the raw requestParameters for the confirmed actor. Determine which tools were called and if any data was exfiltrated.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the absence of agent hijacking activity and update the baseline for tool volume.
```
→ end
