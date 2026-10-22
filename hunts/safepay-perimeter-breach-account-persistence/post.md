# Hunting SafePay Ransomware: Edge Vulnerabilities and Account Persistence

### Why now

CISA recently published [AA26-293A: #StopRansomware: SafePay Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a), detailing the tactics of a group targeting critical infrastructure. SafePay actors rely on common vulnerabilities in edge devices and backup solutions to enter a network. They often maintain access by creating new administrative accounts, a move that provides long-term persistence even if their initial entry point is patched. This hunt targets the gap between the perimeter breach and the deployment of ransomware.

### The hypothesis

An adversary exploits unpatched edge vulnerabilities or uses VPN-based brute force to gain initial access, subsequently creating or elevating accounts to secure administrative persistence. The actor targets devices like Cisco ASA/FTD or Veeam components and frequently uses Mullvad VPN exit nodes to mask their origin. Once inside, they prioritize the creation of new administrative accounts or the addition of users to local and domain admin groups.

### How the hunt flows

The hunt begins by scoping the environment for vulnerable infrastructure. The first query identifies hosts reporting unpatched CVEs associated with SafePay, such as CVE-2024-40766 or CVE-2023-27532. This step defines the primary surface where an intrusion is most likely to originate.

Next, the hunt moves into a parallel analysis phase. One query examines authentication logs for sign-ins originating from Mullvad VPN IPs or known anonymizing proxies. This identifies potential brute force or unauthorized access attempts against the vulnerable infrastructure found in the scoping phase.

Simultaneously, the hunt monitors for persistence markers. Two queries look for account management events: the creation of new user accounts and the addition of users to privileged groups (e.g., Domain Admins or local Administrators). The hunt focuses on changes made by unusual actors or service accounts that do not follow standard provisioning patterns.

In the final phase, an agent or analyst weighs the evidence. A match on a vulnerable host combined with a proxy-based sign-in and a subsequent administrative group change provides a high-fidelity indicator of a breach. This correlation differentiates the hunt from a simple detection rule, which might trigger on a single legitimate admin change but ignore the preceding perimeter signals.

### Blind spots

This hunt depends on the availability of authentication logs. If a VPN appliance or edge device does not forward sign-in events to a central log source, the hunt cannot see the initial access attempts. Additionally, if the adversary uses a private proxy or a new Mullvad exit node not included in current IP lists, the authentication queries may return false negatives. Analysts should verify that edge telemetry is actively flowing before relying on these results.

### How to run it

This hunt is a `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the `hunt.md` format. It is designed to be run periodically or immediately following reports of SafePay activity. Practitioners can adjust the `lookback_days` and `mullvad_ips` parameters to match their specific environment and threat intelligence feeds. The logic pivots from unpatched vulnerabilities to authentication anomalies and account changes, providing the context necessary to confirm a beachhead establishment.
