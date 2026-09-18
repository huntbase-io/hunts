# Hunting for Passkey Phishing and Identity Persistence

Researchers at Microsoft recently detailed a campaign where attackers use passkey lure themes to conduct social engineering. This often involves vishing or SMS to lead users to AiTM phishing sites or into performing device-code authentication. Once a session is hijacked, the attacker typically registers a new MFA method to ensure they can maintain access even if the initial session is revoked. We have published this hunt to help teams identify this specific sequence in their telemetry.

### The Hypothesis
An adversary is using lookalike domains to lure users into AiTM phishing or device-code flows, subsequently hijacking sessions and registering unauthorized MFA methods for persistence. We expect to see a temporal relationship between a DNS resolution to a malicious domain and a rare MFA registration event for the same user account.

### How the Hunt Flows
The hunt begins by identifying the subset of the fleet that interacts with the Microsoft 365 or Azure ecosystem. We query software inventory surfaces for Microsoft-related packages to establish a relevant host list. This narrows the volume of DNS data we need to process in the subsequent steps, focusing our resources on the most likely targets.

Next, we look for DNS resolutions to known phishing and proxy domains identified in the research. These include lookalike domains like 'secure-passkey.com' and 'integratedsso.com'. A hit here does not confirm a breach on its own, but it identifies a user who has interacted with the malicious infrastructure, providing the starting point for our correlation.

We then look at identity behavior through two parallel tracks. The first monitors for successful sign-ins to portals such as OfficeHome or 'My Sign-ins', which are typically visited during session hijacking or account reconnaissance. The second track baselines MFA registration events. We specifically look for the addition of new 'Strong Authentication' methods, such as PhoneAppOTP, that appear for the first time within the lookback window.

In the final triage phase, we correlate the timing of these events. The hunt identifies users who resolved a phishing domain and, within a short window, successfully logged into a management portal and registered a new MFA factor. This specific sequence is what distinguishes a successful compromise from an unsuccessful phishing attempt.

### What the Hunt Cannot See
The primary blind spot is the use of unmanaged devices. If a user opens the lure on a personal phone not monitored by corporate DNS or endpoint agents, we lose visibility into the initial access phase. In these cases, we must rely entirely on identity logs. Additionally, without full schema retention for Entra ID error codes, we may miss specific session-replay indicators that would further confirm the AiTM pattern.

### How to Run This Hunt
This hunt is provided as an open hunt.md playbook. You can import it directly into Huntbase or any hunt.md-aware runtime. It uses parameterization for lookback windows and domain lists, allowing you to update the IOCs as the campaign evolves. Because it correlates three different surfaces, it provides a significantly higher signal than simple domain alerting.

Source: Passkey-themed social engineering leads to identity and cloud compromise (https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)
