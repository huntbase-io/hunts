# Hunting for UNC3753 Vishing and VDI Pivot Behavior

The UNC3753 threat cluster, also known as Luna Moth, has demonstrated significant success in targeting US law firms for data extortion. As detailed by Mandiant in their report [UNC3753 targeted campaign against US law firms](https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms), this group bypasses traditional email security by using vishing. They impersonate IT support or subscription services over the phone to convince victims to install remote monitoring and management (RMM) tools. This hunt focus on the technical bridge where that initial social engineering foothold is used to pivot into the corporate VDI environment.

### The Hypothesis

We hypothesize that an intruder has gained initial access via a vishing call, leading a user to download and install an unauthorized RMM tool (such as SuperOps, AnyDesk, or Zoho) on a host. This host then serves as a bridge, allowing the attacker to sign into corporate VDI infrastructure like Citrix or Windows 365 to begin harvesting sensitive legal documentation.

### How the Hunt Flows

The hunt begins with a scoping phase to inventory the fleet. We focus on endpoints already possessing VDI clients or existing RMM software. This narrows the noise of the subsequent steps by prioritizing hosts that have the necessary software to act as the intended bridge to corporate data.

Next, we look for the specific installation behavior reported in the campaign. This involves searching process telemetry for cURL commands fetching MSI installers and quiet msiexec execution. Specifically, we target the use of SuperOps.msi, which has been a staple of the UNC3753 toolkit.

To corroborate these process findings, the hunt pivots into network and identity logs. We look for DNS resolutions to infrastructure used for payload delivery, specifically privnote.com, which is often used to pass one-time links during a call. Simultaneously, we use prevalence counting across the fleet to identify RMM tools that are only running on a handful of hosts, helping to distinguish shadow IT or actor-directed tools from authorized IT support software.

Finally, we examine VDI authentication logs. We look for successful sign-ins to Citrix or Windows 365. The goal is to find instances where a host that just installed a rare RMM tool or queried a delivery domain is now being used to access the corporate virtual environment.

### Blind Spots and Limitations

This hunt focuses on the technical aftermath. We cannot see the initial vishing phone call or the pretext used by the attacker. Furthermore, if the victim uses a personal BYOD device that lacks managed telemetry, we lose visibility into the RMM installation itself. In those cases, we are limited to seeing the resulting VDI sign-in from an unusual source IP. We also rely on endpoint agent coverage; an unmanaged laptop acting as the bridge will only leave traces in authentication and network logs.

### How to Run This Hunt

This design is a hunt.md playbook. It is intended to be imported into Huntbase or any other hunt.md-aware runtime. Because it relies on prevalence baselines and multi-surface correlation, it is best run as a periodic hunt rather than a point-in-time alert. This allows the analyst to distinguish between routine IT support tasks and the targeted installation of tools used for unauthorized access.
