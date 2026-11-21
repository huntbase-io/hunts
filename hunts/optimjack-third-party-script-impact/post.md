# Hunting OPTIMJACK Supply Chain Compromise in Third-Party Scripts

### Why This Hunt Matters

The OPTIMJACK campaign, detailed by Unit 42 in "Borrowed Code, Real Consequences: What OPTIMJACK Teaches Us" (https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/), demonstrates the fragility of the third-party script ecosystem. Adversaries compromised the Optimizely CDN to inject malicious JavaScript into trusted pages. This script targeted users with mobile exploit kits, making the point of entry a legitimate, certificate-validated domain.

### The Hypothesis

An adversary exploits a trusted third-party vendor to distribute malicious JavaScript via their CDN. This leads to mobile exploit delivery—specifically the Coruna and DarkSword kits—and potential credential skimming on internal corporate assets. Because the initial script arrives from a known-good source, standard domain-blocking lists fail to prevent the initial execution.

### How the Hunt Flows

The hunt begins by scoping interactions with the Optimizely CDN within the `hb_http_activity` surface. This query establishes a candidate pool of hosts that loaded the potentially compromised script during the vulnerability window. By filtering for specific vendor domains, an analyst identifies the extent of exposure across the workstation fleet.

Next, the hunt pivots to triage evidence of the follow-on exploit stage. Two parallel queries search `hb_http_activity` and `hb_dns_activity` for keywords associated with the Coruna and DarkSword exploit kits. This phase looks for the actual delivery of the mobile payload or the resolution of attacker-controlled infrastructure.

In the final analysis phase, an analyst correlates the CDN interactions with the exploit kit markers. A host that visits the CDN and then immediately requests an exploit kit payload receives a malicious verdict. This correlation allows the hunt to find high-confidence compromise signals without alerting on every legitimate script load.

### What the Hunt Cannot See

The hunt faces two primary visibility challenges. First, if the proxy gateway does not perform SSL/TLS decryption, full URL paths for exploit kit requests remain hidden. The hunt then relies on DNS telemetry, which may lack the granularity needed for certain exploit patterns. Second, the campaign targets mobile devices. If an employee uses an unmanaged iPad or iPhone that does not route traffic through corporate inspection, the exploitation stage remains invisible to internal telemetry.

### Why This is a Hunt

This is a hunt because it correlates legitimate activity (CDN usage) with rare malicious follow-on activity across multiple surfaces. A single rule on Optimizely CDN traffic would be far too noisy to be actionable; an analyst must weigh the presence of exploit-kit markers against the CDN interaction to reach a verdict.

### How to Run It

This hunt is available as an open `hunt.md` playbook. You can import it into Huntbase or any compatible runtime. The design gates forensic actions behind evidence correlation, ensuring that incident response resources focus on hosts with verified exploit kit delivery rather than general CDN usage.
