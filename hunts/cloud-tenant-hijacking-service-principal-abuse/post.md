# Hunting Cloud Tenant Hijacking and Service Principal Abuse

### Why now

Recent research titled The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime (https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/) details how adversaries hijack legitimate M365 tenants to host phishing materials. These actors, such as Storm-3119, bypass standard user-level detections by abusing application-only authentication. Once they control a service principal, they scale their operations across SharePoint and OneDrive. We published this hunt to help practitioners find the specific trail left during this takeover process.

### The hypothesis

An adversary uses stolen application secrets for application-only authentication to hijack M365 tenants. After gaining access, the actor escalates privileges via the Graph API to host phishing infrastructure on SharePoint and OneDrive, often using administrative tools like the PnP Management Shell to automate the setup.

### How the hunt flows

The hunt begins with a scoping phase to identify every active M365 tenant within the environment. This step uses the `hb_cloud_api_activity` surface to narrow the investigation to active accounts and services, ensuring the analyst only triages relevant telemetry.

In the second phase, the hunt identifies anomalous access patterns. It queries the `hb_auth_signin` surface for two specific signals: logins originating from known proxy or anonymizing infrastructure and authentication flows that use application secrets or client credentials rather than user sessions. An analyst then assesses whether these principals represent known service accounts or unexpected beachheads.

Third, the hunt pivots to privilege escalation and resource abuse. It returns to `hb_cloud_api_activity` to find evidence of the adversary self-provisioning the PnP Management Shell or granting sensitive directory permissions like AppCatalog.ReadWrite.All. These actions allow the attacker to control organizational storage for malicious hosting.

Finally, the hunt monitors for persistence and manipulation. It looks for service principals performing high-volume administrative tasks that are rare for the environment, such as bulk password resets or license assignments. The process concludes by correlating the initial access anomalies with these administrative abuses to confirm a persistent takeover.

### What the hunt cannot see

This hunt faces two primary blind spots. First, if an adversary steals an application secret months before they begin manipulation, the initial access may fall outside the 90-day retention limit of most cloud audit logs. Second, the telemetry often shows which application authenticated but does not always specify which client secret ID the actor used. This makes it difficult to confirm if a specific secret was leaked until the app is audited.

### How to run the hunt

This hunt is an open `hunt.md` playbook. You can import it directly into Huntbase or any runtime that supports the hunt.md standard. The playbook includes the logic to scope your tenants, triage the authentication flows, and analyze the full attack chain. Because this is a hunt rather than a static detection, it focuses on the correlation of events that indicate a systematic environment hijacking.
