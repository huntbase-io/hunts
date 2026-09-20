# Hunting Interlock RAT via PHP Execution and Discovery Behaviors

### Why this hunt?

In a recent report titled KongTuke FileFix Leads to New Interlock RAT Variant (https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/), The DFIR Report details a campaign where the Interlock ransomware group deployed a PHP-based Remote Access Trojan (RAT). This successor to NodeSnake arrives via a PowerShell stager and hides within user-writable directories. Because the actor uses legitimate interpreters like PHP and common discovery commands, simple detections often fail or create too much noise. This hunt correlates the specific deployment path, command-line telemetry, and network callbacks to confirm active infections.

### Hypothesis

An intruder has deployed a PHP-based RAT into user-writable directories via a PowerShell stager and is conducting automated system reconnaissance to map the environment.

### How the hunt flows

The first phase scopes the environment for the arrival of the RAT. The query looks for PHP executables running from the Roaming AppData directory. While developers might occasionally run PHP in user paths, this location is a hallmark of the Interlock campaign's delivery method.

The second phase pivots to network and baseline evidence. We correlate these rare PHP process paths with DNS activity involving Cloudflare Tunnel domains. The actor uses trycloudflare.com subdomains to tunnel C2 traffic. By stacking PHP paths across the fleet, we isolate outliers that deviate from standard developer or application behavior.

The third phase analyzes post-infection behaviors. The hunt searches for a specific cluster of discovery commands, such as get-netneighbor and systeminfo, which the RAT uses to profile the host. We also look for Registry Run key modifications that point back to the PHP interpreter and associated configuration files to confirm established persistence.

The final phase synthesizes these findings. An analyst or automated agent weighs the presence of the rare binary against the reconnaissance activity and known configuration file hashes. This multi-stage approach ensures that we only flag hosts where the full lifecycle of the Interlock RAT is visible.

### Blind spots and limitations

This hunt relies heavily on process command-line auditing. If an endpoint does not report full command lines, we cannot see the automated reconnaissance or the specific PHP arguments used for the RAT. Furthermore, the Cloudflare Tunnel subdomains are ephemeral. If the adversary rotates to new domains not included in our parameters, the DNS enrichment step will return zero results.

### How to run it

We provide this hunt as an open hunt.md playbook. This format allows you to import the logic directly into Huntbase or any security platform that supports hunt.md runtimes. It organizes the queries into a logical flow, starting with broad scoping and moving to high-fidelity behavioral analysis.
