# Hunting for Platform-as-a-Proxy Phishing and Input Abuse

### The Shift to Platform Abuse
Threat research from Talos, [Parasitizing trust: How legitimate infrastructure becomes a delivery pipeline for attackers](https://blog.talosintelligence.com/parasitizing-trust-how-legitimate-infrastructure-becomes-a-delivery-pipeline-for-attackers/), highlights a shift in social engineering tradecraft. Adversaries no longer rely solely on compromised mail servers. Instead, they subvert the Platform-as-a-Proxy model. They inject malicious content, such as fraudulent helpline numbers, into the registration forms or transactional fields of trusted providers like Staples and Dell. These platforms then send high-reputation notifications to targets, laundering the attack through legitimate infrastructure.

### The Hypothesis
An adversary uses trusted third-party retail or SaaS infrastructure to deliver social-engineering lures. They achieve this by injecting fraudulent helpline numbers into transactional notification fields or abusing public-facing registration forms to trigger reflexive notifications. These emails originate from trusted domains and pass authentication checks, allowing them to bypass traditional email security gateways and landing directly in user inboxes.

### Phase 1: Scoping and DNS Leads
The hunt starts by identifying hosts running productivity and communication suites. This scoping step focuses the investigation on systems where users engage with mail notifications or where automated scripts might interact with external forms. We then use a low-cost lead by checking DNS activity for brand domains associated with order processing. Because organizational traffic to these domains is common, we do not alert on the lookup. Instead, we baseline normal activity to find anomalous resolution patterns that suggest the arrival of a fraudulent notification.

### Phase 2: Analyzing Content and Proxy Traffic
Once a suspicious lead is confirmed, the hunt gates into parallel analysis. The first branch searches Microsoft 365 Unified Audit Logs for social engineering keywords in subject lines, such as "helpline" or "order confirmed." This correlates the timing of the notification with the previous DNS lead. The second branch examines outbound HTTP traffic for POST requests to registration endpoints. It looks for lures like "crypto" or "bitcoin" in query parameters, identifying the input stage where a host triggers notifications to external targets.

### Why This Is a Hunt
Static detection rules struggle with Platform-as-a-Proxy attacks because the traffic originates from known-good IP addresses with valid certificates. Alerting on every resolution of order domains or every automated notification creates excessive noise. This hunt provides context by correlating activity across DNS, cloud audit logs, and web proxies. We only investigate when the resolution of a retail domain coincides with the arrival of a message containing specific lure keywords, isolating the subversion attempt from legitimate commerce.

### Blind Spots
The hunt cannot identify DNS resolutions if a host uses an external resolver that bypasses local logging. In M365 logs, we see subjects and metadata but cannot inspect the email body. A manual review is necessary to confirm the presence of specific fraudulent phone numbers. Additionally, if an adversary sends the hostile string in the request body rather than the URL query parameters, standard HTTP logging may miss the injection attempt.

### How to Run
This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. The design uses a gated flow to manage resources, ensuring that the most intensive searches only run after you identify a valid lead in your environment telemetry.
