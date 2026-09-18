# Hunting Spring Ring Persistence and NTLM Relay Patterns

The Spring Ring campaign, recently detailed by Unit 42 in their report "Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams," demonstrates how vishing can quickly escalate from a simple chat to a domain-level takeover. Specifically, Campaign B involves a series of endpoint and network behaviors that evade common detection logic by blending into standard developer or administrative activity. This hunt provides a structured approach to identifying these post-compromise stages.

Our hypothesis is that an adversary is establishing persistence using tailored executables in the Temp directory and initiating a Python-based NTLM relay attack to achieve domain-level takeover. The hunt targets the specific toolkit used by the Spring Ring actors, including the staging of a specialized Python environment for lateral movement.

The hunt begins by scoping the environment for known indicators of the Spring Ring campaign. We look for a specific Python interpreter staged in ProgramData and binaries in the user Temp folder using observed naming prefixes like 'vhlp-' and 'scnr-'. This scoping step provides a candidate list of hosts that warrant deeper forensic inspection.

Next, we pivot to process flags associated with defense evasion. The hunt identifies instances of Microsoft Edge running in headless mode with the extension sideloading flag enabled. This technique is used to manipulate browser sessions and potentially steal credentials. We isolate these events to identify browser instances that deviate from standard interactive user behavior.

We then examine the persistence mechanism by looking for rare binaries in the Temp folder. By filtering for the observed naming conventions and calculating the rarity of these files across the fleet, we can distinguish between common software updaters and targeted attacker payloads. This step helps identify the tailored executables described in the Unit 42 analysis.

Finally, the hunt correlates the staged Python environment with network activity. We specifically look for SMB connections originating from the malicious Python interpreter path. This pattern is indicative of PetitPotam-style NTLM relay attacks used to move laterally or compromise domain controllers. Combining the process path and the destination port allows us to identify the relay activity with higher confidence.

There are necessary blind spots in this approach. We cannot see the internal code of the sideloaded browser extensions without manual file collection. Additionally, without protocol-level SMB analysis or domain controller auditing, it can be difficult to distinguish between a specific PetitPotam coercion attempt and general administrative scanning. These findings require manual review of the captured artifacts.

This is designed as a hunt rather than a detection rule because the individual components—headless browsers, Python network activity, and Temp folder execution—are frequent in many enterprise environments. The value lies in the correlation of these surfaces. This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to begin your investigation.
