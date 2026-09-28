# Hunting CVE-2026-19490 Citrix NetScaler Authentication Bypass

### Why this hunt matters

[Rapid7](https://www.rapid7.com/blog/post/etr-cve-2026-19490-critical-vulnerability-affecting-citrix-netscaler-adc-and-netscaler-gateway) recently detailed CVE-2026-19490, a critical vulnerability affecting Citrix NetScaler ADC and NetScaler Gateway appliances. This flaw allows an unauthenticated attacker to bypass authentication mechanisms and gain unauthorized remote access. Because these appliances serve as primary gateway controllers for corporate networks, an unauthenticated bypass represents a high-severity threat that requires immediate verification of the perimeter.

### The Hypothesis

An unauthenticated attacker has exploited CVE-2026-19490 on an internet-facing NetScaler appliance to bypass authentication and gain unauthorized remote access.

### How the Hunt Flows

The first phase scopes the environment to identify vulnerable targets. The hunt queries the vulnerability management surface for any Citrix NetScaler appliance with an unresolved finding for CVE-2026-19490. This step narrows the investigation to systems where the exploitation risk is confirmed.

The second phase analyzes the prevalence of successful authentications across the estate. We examine source IP addresses that have successfully logged into only one or two appliances within the last 14 days. While legitimate employees often connect to multiple gateway services, an attacker exploiting a bypass usually originates from a unique IP address that deviates from the established baseline of corporate user behavior.

The third phase inspects HTTP activity for anomalous patterns targeting sensitive endpoints. The hunt monitors traffic directed at paths related to SAML and VPN logons. We specifically look for successful status codes returned for requests that lack the typical session precursors. By correlating these web access patterns with the rare source IPs identified in the previous step, an analyst can pinpoint evidence of a successful authentication bypass.

### What This Hunt Cannot See

This hunt depends entirely on the appliance forwarding logs to a central telemetry provider. If the NetScaler is not configured to send Syslog for HTTP activity or authentication events, the queries will return no results even if exploitation is occurring. Additionally, if the exploit occurs at a protocol level that the appliance does not log as a standard sign-in event, the authentication prevalence query may miss the initial entry point.

### How to Run It

We provide this hunt as an open hunt.md playbook. You can import it into Huntbase or any other runtime that supports the hunt.md standard. This format allows you to run the queries as a structured workflow, facilitating the transition from automated scoping to manual triage and remediation.
