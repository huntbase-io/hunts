# Hunting for Malicious Redirection and Lures on AI Platforms

### Why this hunt

Threat actors increasingly abuse the high domain reputation of legitimate AI platforms to bypass security controls. Research from Huntress in [The AI Attack Surface: How Threat Actors Abuse Trusted AI Platforms](https://www.huntress.com/blog/ai-attack-surface) details how adversaries use features like Claude Artifacts or shared ChatGPT conversations to host malicious lures. Because these platforms are widely trusted, a standard block is rarely feasible. We focus on the specific chain of events where a user moves from a trusted AI domain to a malicious secondary delivery site.

### The Hypothesis

An intruder abuses trusted AI platforms such as Claude or ChatGPT to host malicious redirection lures via SEO poisoning. They funnel users from legitimate AI domains to secondary malware delivery infrastructure to establish initial access.

### How the hunt flows

The hunt begins with a broad scoping phase. The first query identifies every host that resolves known AI domains. This establishes a baseline of AI usage across the fleet and narrows the investigation to hosts with the potential to interact with AI-hosted lures.

Next, the hunt pivots into three parallel checks on the scoped hosts. It looks for rare HTTP paths associated with shared content, such as specific artifacts or shared conversation IDs that appear on only a few hosts. Simultaneously, it checks for network connections to known malicious redirectors identified in current threat research. A third check monitors for browser-spawned shell processes, a common indicator of 'ClickFix' lures where a site instructs a user to run a command manually.

An analyst or automated agent then evaluates these signals. The hunt looks for a temporal link: did the host visit a rare AI path and then immediately connect to a redirector or launch a terminal? This correlation separates standard AI usage from a successful redirection chain.

### Blind Spots

This hunt relies heavily on URI visibility. Without TLS decryption, the hunt can identify that a host visited a root domain like claude.ai, but it cannot see the specific path components like `/artifacts/`. This makes it harder to distinguish a malicious lure from general platform use. Furthermore, the hunt uses a list of known malicious domains. If an attacker rotates their delivery infrastructure to a new domain not included in the parameters, the network connection check will not fire.

### How to run it

This hunt is provided as an open `hunt.md` playbook. You can import this file directly into Huntbase or any hunt.md-aware runtime. The playbook includes the logic to scope your environment, run the parallel behavioral checks, and provide a per-host verdict based on the correlated evidence.
