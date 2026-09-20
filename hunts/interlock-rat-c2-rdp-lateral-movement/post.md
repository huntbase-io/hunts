# Hunting for Interlock RAT C2 and RDP Lateral Movement

### Why Now

The DFIR Report recently detailed a campaign where attackers deploy a modular PHP payload and maintain access through encrypted tunnels. You can read their full analysis in [KongTuke FileFix Leads to New Interlock RAT Variant](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/). This hunt identifies the specific indicators of this Interlock RAT variant.

### The Hypothesis

An intruder establishes a PHP-based Remote Access Trojan (RAT) beachhead and uses Cloudflare Tunnels for command-and-control. They maintain access through these tunnels before moving laterally via RDP to other systems in the environment.

### How the Hunt Flows

The hunt starts by examining DNS activity. The first query searches for any resolution of specific `trycloudflare.com` subdomains identified in the campaign. These resolutions serve as the primary indicator of a potential beachhead system communicating with attacker infrastructure.

When the hunt identifies a lead, it triggers a parallel investigation across three surfaces. It searches for network connections to hardcoded fallback IP addresses, looks for the `php.exe` process executing with specific configuration flags from user roaming profiles, and identifies rare RDP logon events. This phase gathers the behavioral evidence needed to confirm the RAT's presence and activity.

An automated agent then correlates these results. It compares the hosts resolving C2 domains with the hosts showing suspicious PHP execution or initiating outbound RDP sessions. This correlation joins network-level leads with host-level behavior to provide a high-confidence verdict.

Confirmed infections route to an isolation step to prevent further spread. The hunt concludes with a manual task for an analyst to review the intrusion timeline and identify any accounts the intruder compromised during their lateral movement.

### What This Hunt Cannot See

This hunt faces visibility gaps regarding local authentication. If an intruder moves between systems using local accounts or sessions not captured by centralized authentication providers, the RDP queries will not show that movement. 

Legitimate administrative use of Cloudflare Tunnels also creates potential noise. While the hunt targets specific subdomains, the behavior of the tunnel itself can look similar to authorized activity. The hunt relies on the presence of the PHP behavioral artifacts to differentiate the RAT from legitimate tools.

### How to Run It

This hunt is an open `hunt.md` playbook. You can import it into Huntbase or any hunt.md-aware runtime. It uses the specific C2 indicators and behavioral patterns from The DFIR Report to search your telemetry for Interlock RAT activity.
