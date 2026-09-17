# Proactive Hunting for Passkey-Themed Phishing Infrastructure

### Why Now

A recent report from the [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/) highlights a sophisticated social engineering campaign. Attackers are leveraging the transition to passkeys as a lure, directing employees via phone or SMS to organization-themed subdomains like `company-name.integratedsso.com`. Because these domains are often fresh and specific to a single target, they frequently bypass traditional reputation-based filters.

### The Hypothesis

We hypothesize that the initial stages of this campaign are visible within internal networks as rare DNS queries or HTTP requests. While the lure might arrive on a personal device, the subsequent interaction with the phishing portal often occurs on managed workstations through shared browsers or corporate chat links. By monitoring for specific keywords and using prevalence-based filtering, we can identify these domains before the threat actor successfully replays a session token.

### How the Hunt Flows

The hunt begins by scoping to managed workstations. These devices provide the most consistent telemetry for both network activity and process context, allowing us to build a more accurate baseline of what "normal" authentication traffic looks like for a specific fleet.

The search phase runs in parallel across three fronts. First, we check for direct matches against known IOCs reported by Microsoft. Simultaneously, we perform a prevalence-based search for rare domain resolutions containing keywords like "passkey," "integratedsso," or "oktasession." We filter these by counting the unique hosts querying them; legitimate SaaS providers will typically appear across many hosts, while targeted phishing infrastructure will appear on only a few.

To add depth, we corroborate these network hits with HTTP metadata. This allows us to inspect User-Agents and URL paths. Attackers often use specific toolkits or frameworks that leave unique footprints in the HTTP headers, or they may direct users to specific paths that differ from standard SSO redirection flows.

Finally, the hunt uses an agent-assisted triage to weigh the evidence. It evaluates whether a host's interaction with a domain suggests a legitimate service or a high-confidence phishing attempt, allowing for rapid response such as host isolation or session revocation.

### Blind Spots

This hunt has two primary limitations. First, if a browser is configured to use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) to an external resolver, the standard DNS activity logs will be empty. Second, if the entire social engineering interaction and subsequent compromise occur on a personal mobile device outside the corporate management boundary, this hunt will not see the infrastructure setup. In those cases, the first signal would be found in identity provider sign-in logs.

### How to Run It

This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any other `hunt.md`-aware runtime. Because it relies on prevalence-based baselining rather than just static lists, it remains effective even as adversaries rotate their specific subdomains.

Source: Microsoft Security Blog — Passkey-themed social engineering leads to identity and cloud compromise
