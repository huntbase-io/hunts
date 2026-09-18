# Hunting Knight Office AiTM Phishing and Device Code Session Theft

Adversaries are increasingly leveraging Adversary-in-the-Middle (AiTM) kits to bypass multi-factor authentication (MFA). A recent analysis by Huntress, [Inside Knight Office, a New M365 AiTM Phishing Kit](https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack), highlights a specific campaign using the Device Code authentication flow. This method is particularly effective because it shifts the burden of authentication to a trusted Microsoft endpoint, making the phishing site appear less suspicious to both the user and traditional security filters.

### The Hypothesis

We hypothesize that an adversary is using trusted SaaS platforms (like Monday.com or Notion) as initial redirectors. These redirects lead users to infrastructure hosted on rare .vu top-level domains. Once on the site, the victim is prompted to enter a device code at the legitimate Microsoft login page, allowing the adversary to capture session tokens via residential proxies to blend with normal traffic.

### How the Hunt Flows

The hunt begins with a scoping phase using `hb_devices`. We focus our telemetry review on hosts with naming conventions suggesting high-value targets, such as executive, finance, or treasury departments. This prioritization ensures that if session theft is occurring, we investigate the most impactful potential compromises first.

Next, we establish a baseline for .vu domain resolutions across the fleet using `hb_dns_activity`. Because .vu is a rare TLD in most corporate environments, identifying domains seen on only a handful of hosts allows us to isolate potential phishing infrastructure that has not yet been blacklisted by reputation services.

We then move into the correlation phase using `hb_http_activity`. We look specifically for a behavioral sequence: an HTTP request where the referrer is a high-reputation SaaS domain and the destination is a .vu domain. Simultaneously, we monitor for any host that visits the Microsoft `/devicelogin` endpoint. While this endpoint is used legitimately for IoT and developer tasks, seeing it immediately following a .vu redirection is a strong indicator of the Knight Office kit in action.

Finally, we check `hb_network_connection` for any direct hits against known infrastructure associated with the kit's console and delivery points. The hunt concludes with a triage step where an agent evaluates these disparate signals—SaaS redirects, rare DNS, and device login activity—as a single coordinated attack chain.

### What This Hunt Cannot See

There are necessary boundaries to this hunt. Because we rely on endpoint and network telemetry, we do not have visibility into the original email body or subject. We cannot see if the adversary used character substitution (like 'lmportant') in the lure itself. Furthermore, without deep TLS decryption or specific residential proxy intelligence, we cannot see the exact device code being entered or definitively prove a source IP is a proxy without third-party metadata. We are looking for the behavioral 'smoke' of the redirection and the login flow.

### How to Run It

This hunt is provided as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime capable of parsing the hunt.md format. By defining your high-risk host patterns and kit-specific indicators as parameters, you can execute this across your fleet to identify active session capture attempts before the adversary successfully registers a rogue device or establishes persistence.
