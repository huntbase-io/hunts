# VerdantBamboo Credential Abuse and Edge Appliance Pivot Hunt

### Why now

Volexity recently published [VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall](https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/), detailing an adversary's persistence on edge appliances. The actor targets systems like Egnyte Storage Sync and Synology NAS to gain a foothold. They use stolen credentials to access these devices via VPN or SSH, often bypassing multi-factor authentication (MFA) by coming through established tunnels. This hunt helps teams identify if their edge perimeter shows signs of this administrative abuse.

### The hypothesis

An adversary uses stolen administrative or service account credentials to access edge appliances via VPN or SSH. They subsequently use web-based management interfaces to pivot further into the network or deploy persistence mechanisms like the PLENET backdoor.

### How the hunt flows

The first phase scopes the environment. A query pulls software inventory data to locate any hosts running software from Egnyte, Synology, or pfSense. This identifies the systems most likely to be targeted or used as a pivot point by the VerdantBamboo actor.

Once the hunt defines the scope, it moves to parallel evidence gathering. One branch examines sign-in logs for administrative users like `egnyteservice` or `root`. It stacks these logins by source IP. The logic focuses on source IPs that connect to only one or two hosts, which helps separate rare actor activity from broad MSP or IT maintenance patterns. 

The second branch monitors HTTP activity for access to appliance management paths. It looks for requests containing strings like `/webman/` or `/syno/`. While many organizations use these interfaces regularly, the hunt flags instances where these paths are accessed from the same rare source IPs identified in the authentication logs.

In the final phase, an analyst or automated agent correlates these signals. If a host shows both a rare administrative login and subsequent web management activity, the hunt transitions to a triage state. The playbook then provides instructions for isolating the appliance and performing forensic verification for specific malware like the AGENTPSD Python shell.

### What this hunt cannot see

This hunt has two primary blind spots. First, it relies on HTTP and authentication logs. If the adversary executes commands directly on the appliance shell after an SSH login, we cannot see those process-level details without a local EDR agent or detailed syslog from the device itself. Second, if the authentication logs only capture an internal VPN IP address, the hunt may struggle to distinguish between a compromised employee and an external actor without correlating logs from the VPN gateway.

### How to run it

This hunt is provided as an open `hunt.md` playbook. You can import it into Huntbase or any other `hunt.md`-aware runtime. The playbook uses standard SQL queries against software inventory, authentication, and HTTP surfaces. It is designed to run periodically to validate that administrative access to your edge appliances remains legitimate.
