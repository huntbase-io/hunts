# Hunting for BRICKSTORM Backdoors in Edge Appliances

### Background
In recent research, Volexity detailed the activities of a threat actor tracked as VERDANTBAMBOO. This group focuses on compromising unmanaged edge infrastructure—including storage sync appliances and firewalls—to establish a foothold within target environments. Their primary tool, the BRICKSTORM backdoor, is notable for its use of DNS-over-HTTPS (DoH) to bypass traditional network monitoring. You can read the full technical details in the Volexity report: [VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall](https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/).

### Hypothesis
This hunt is based on the premise that an intruder has compromised an edge appliance using stolen credentials, escalated privileges via a `sudo` misconfiguration, and deployed the BRICKSTORM backdoor. We expect to find evidence of persistence in system-level cron directories and outbound network traffic to public DNS resolvers via port 443.

### The Hunt Flow

The hunt starts with **Scoping**, identifying Linux and BSD-based systems within the environment. Because many edge appliances run specialized versions of these operating systems, we must first isolate these hosts to ensure our behavioral queries are targeted at the correct infrastructure.

We then move to **Authentication Anomalies**, specifically looking for successful logins to service accounts like `egnyteservice` or VPN-related providers. In the VerdantBamboo campaign, attackers often used legitimate but stolen service account credentials to gain their initial foothold.

Next, the hunt examines **Process Activity** for the misuse of `sudo tee`. This specific pattern is used by the attacker to overwrite sensitive system configuration files. While `sudo tee` is a common administrative command, its appearance on a production appliance followed by file writes to system directories is a significant indicator of compromise.

For **Network Telemetry**, we focus on outbound connections to public DNS resolvers like 8.8.8.8 on port 443. Since BRICKSTORM leverages DoH for command-and-control, these connections appear as standard HTTPS traffic. We look for persistent, low-volume connections from appliance processes that lack corresponding standard DNS traffic.

Finally, we audit **Persistence** by inspecting `/etc/cron.d/` and other system crontabs. We are looking for unauthorized entries that execute shell scripts or interpreters, which the actor uses to ensure their implant remains active across reboots.

### Blind Spots and Limitations
The primary blind spot for this hunt is telemetry coverage. If an appliance is a proprietary "black box" that does not support the installation of an endpoint agent, process and file activity signals will be unavailable. Furthermore, without TLS inspection at the network layer, we cannot confirm the content of DoH traffic; we must rely on destination IPs and connection frequency as behavioral proxies.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. This format allows the hunt to be imported into Huntbase or any other `hunt.md`-aware runtime. It is designed to be a point-in-time audit rather than a static detection rule, as many of the indicators (like `sudo tee` or DoH traffic) require human context to distinguish from legitimate vendor maintenance activity.
