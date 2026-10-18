# Hunting Unauthorized VPN Access Following WatchGuard Phishing

### The Threat

Huntress recently detailed a campaign where attackers use lookalike WatchGuard download sites to harvest VPN credentials (https://www.huntress.com/blog/fake-watchguard-vpn-credential-phishing). These sites deliver legitimate installers while silently exfiltrating cleartext passwords. Once they obtain credentials, the adversaries attempt to establish a foothold within the corporate network.

Adversaries use credentials stolen from lookalike WatchGuard VPN download sites to authenticate to corporate VPNs from anomalous geographic regions or hosting provider IP space. Because these logins use valid credentials, they often bypass traditional security controls that do not account for behavioral shifts post-authentication.

### How the Hunt Flows

The first phase identifies every active VPN gateway in the environment. The hunt queries authentication logs for service names and destination endpoints containing VPN-related keywords. This scoping step ensures the analyst focuses only on the systems acting as the perimeter entry point for remote users.

In the second phase, the hunt runs a parallel analysis of source rarity and user behavior. One branch stack-counts successful VPN logins by country and city to find locations associated with three or fewer users. A second branch collects high-impact cloud API operations, such as creating, updating, or deleting resources, performed during the lookback window.

The final phase correlates these findings. An analyst evaluates whether a login from a rare country or a known proxy precedes significant cloud modifications. This correlation reduces the false positives typical of simple geo-fencing by requiring evidence of impactful activity following the suspicious login. If the session appears unauthorized, the hunt provides a path to revoke the session and lock the account.

### Blind Spots

This hunt relies entirely on the ingestion of VPN gateway authentication logs into a central data lake. If an organization runs an unmonitored appliance or an external service that does not export sign-in events, the hunt cannot see the access. 

Additionally, attackers increasingly use residential proxy services to mimic the home networks of legitimate users. If an adversary uses a residential IP located in the same country or city as the victim, the statistical rarity check may fail to trigger. Identifying these sessions requires advanced IP reputation data that distinguishes residential ISPs from commercial data centers.

### Running the Hunt

This playbook is formatted as a `hunt.md` file. It imports directly into Huntbase or any security platform that supports the hunt.md specification. Analysts can adjust the lookback window or scope specific VPN hostnames to fit their environment during execution.
