# Hunting SafePay Initial Access and Identity Consolidation

### Why this hunt
CISA recently published [#StopRansomware: SafePay Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a) regarding the tactics used by this group. SafePay operators focus on rapid entry through vulnerable edge infrastructure, specifically Cisco VPNs, Veeam backup servers, and SonicWall firewalls. Once inside, they move quickly to solidify their presence by creating administrative accounts. We designed this hunt to find the transition from the initial exploit to the establishment of persistent control.

### Hypothesis
An adversary has exploited a known edge vulnerability to gain a foothold and is consolidating control by creating administrative accounts and escalating local privileges via UAC bypass.

### Hunt Flow
The first phase uses the `hb_vulnerability_finding` surface to scope the environment. It checks for specific CVEs associated with SafePay, such as CVE-2024-40711 and CVE-2023-20269. This step acts as a gate. If no vulnerable assets report in, the hunt stops. This prevents an analyst from sifting through logs on hosts that were never at risk for this specific entry vector.

Once an exposure is confirmed, the hunt fans out into three parallel behavioral investigations. The first query examines `hb_auth_signin` for brute-force patterns or anomalous sign-in volumes targeting the exposed hosts. This identifies if the adversary attempts to pivot from an exploit to credential-based access or if they are testing stolen credentials.

The second query monitors `hb_account_change` for persistence indicators. It looks for new account creations or password resets on critical servers. This behavior often marks the transition from a temporary foothold to a more permanent administrative presence. The hunt looks for activity that deviates from standard administrative windows.

The third query targets privilege escalation via `hb_process_activity`. It identifies high-integrity processes spawned from interactive shells like `cmd.exe` or `powershell.exe`. While these actions occur during legitimate administration, their coincidence with vulnerable edge states increases the likelihood of a UAC bypass. 

Finally, an agent synthesizes these signals. It weighs the vulnerability status against the observed behaviors to provide a host-by-host verdict. If the evidence shows both account manipulation and privilege escalation on a vulnerable host, the hunt suggests immediate isolation to stop the adversary before they begin data exfiltration or encryption.

### Blind Spots
This hunt depends on the accuracy of the vulnerability inventory. If a firewall or VPN gateway does not report its status to the `hb_vulnerability_finding` surface, the scoping phase will ignore it. Analysts must ensure all edge devices are correctly enrolled and scanned. Additionally, the hunt may miss account changes if they occur directly on a Domain Controller that lacks an endpoint agent, as it relies on the `hb_account_change` surface for visibility.

### How to Run
This hunt is an open `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the `hunt.md` format. The parameters allow for a custom lookback window and specific host scoping if you already have a lead from an external threat intelligence report. Unlike a standard detection, this hunt correlates vulnerability state with behavior, reducing false positives from legitimate IT maintenance.
