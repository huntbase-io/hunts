# Hunting Interlock PHP RAT Persistence and Lateral Movement

### Why Now
Research from The DFIR Report, [KongTuke FileFix Leads to New Interlock RAT Variant](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/), details a shift in the Interlock group's tooling. They have adopted a PHP-based Remote Access Trojan (RAT) that utilizes Cloudflare Tunnels for command and control. This shift suggests an attempt to bypass detections built for their previous Node.js-based toolsets. If an environment is compromised, the primary indicators are often buried in standard user-profile activity.

### The Hypothesis
An adversary has maintained access using a PHP-based RAT that persists via registry Run keys and is moving laterally through the environment using RDP. We expect to see PHP binaries executing from non-standard paths, specifically user-writable AppData directories, loading encrypted configuration files.

### How the Hunt Flows
The hunt begins with scoping: identifying any PHP interpreters running from `AppData\Roaming`. Specifically, we look for command lines referencing `.cfg` files, which the Interlock RAT uses for its configuration. This initial sweep narrows the focus to hosts where the RAT may have been deployed.

Next, we corroborate this with persistence evidence. We query the Registry Run keys for entries that automate the execution of these PHP binaries. Seeing a match here confirms that the threat is intended to survive reboots and is not a transient process.

To confirm command and control, the hunt pivots to network telemetry. We look for DNS queries to the `trycloudflare.com` domain, which is used for the RAT’s primary tunnel. We also check for direct outbound connections to known hardcoded fallback IPs, which bypasses DNS entirely and serves as a high-fidelity indicator of malicious intent.

Finally, we examine lateral movement by stacking internal RDP connections. We look for rare pairs—outbound RDP connections from the suspected hosts to internal targets that occur infrequently. This helps separate legitimate administrative activity from an adversary traversing the network.

### Blind Spots
There are two primary limitations to this hunt. First, unmanaged hosts or assets without endpoint agent coverage will not appear in the process or registry logs. Second, while we can see RDP network traffic, this hunt lacks the authentication context (such as logon type) to distinguish between automated scripts and interactive sessions. Analysts should verify these findings against authentication logs.

### How to Run the Hunt
This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any hunt.md-aware runtime. Because it correlates activity across process, registry, and network surfaces, it is designed to be triaged by an agent or a human analyst to verify the combination of indicators before taking isolation actions.
