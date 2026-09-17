# Hunting VerdantBamboo Identity Misuse and Internal Appliance Proxying

The recent analysis by Volexity, [VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall](https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/), details how UNC5221 leverages compromised credentials and internal appliance vulnerabilities. A key component of their tradecraft is using internal Linux-based appliances as proxies to blend in with legitimate corporate traffic and circumvent security controls.

Our hypothesis is that an adversary, after gaining initial access via VPN, moves to internal appliances—such as Egnyte Storage Sync or Synology NAS—to reach Microsoft 365. This allows the attacker to present an internal source IP to the SaaS provider, effectively neutralizing Conditional Access policies that white-list the corporate network egress.

The hunt flow begins with scoping. Using the `hb_devices` surface, we identify hosts matching the naming conventions of targeted appliances. These devices often lack traditional EDR coverage, making them ideal blind spots for long-term persistence and proxying.

Next, the hunt pivots to `hb_auth_signin` to identify Microsoft 365 authentication events originating from internal private IP addresses. In a standard configuration, cloud-based logins should originate from external gateway IPs. Finding internal IPs here is a strong indicator of a proxy or tunnel being used within the perimeter.

Simultaneously, we examine VPN authentication patterns. We look for rare user-IP pairs where a successful login occurs from a source IP not previously associated with that specific user. This helps identify the initial credential misuse that precedes the appliance pivot.

Finally, we check the `hb_network_connection` surface for outbound SSH or HTTPS traffic initiated by the identified appliances. These devices typically function as servers or sync targets and should rarely initiate outbound management connections to other internal servers or cloud IPs.

This hunt has two significant blind spots. First, short VPN log retention may prevent us from seeing the initial entry point if the compromise occurred weeks ago. Second, because many appliances do not support security agents, we cannot see the execution of backdoors like PLENET or AGENTPSD directly on the disk; we must rely entirely on the network and authentication telemetry they generate.

This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any compatible runtime to automate the correlation across these disparate surfaces.
