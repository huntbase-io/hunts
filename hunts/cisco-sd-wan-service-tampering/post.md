# Cisco SD-WAN Controller Service Tampering

### Why now

- Cisco Talos recently detailed historical activity from UAT-11473, a cluster using the [KeyDrift](https://blog.talosintelligence.com/uat-11473-keydrift/) framework to compromise Cisco SD-WAN controllers. These controllers, including vSmart, vManage, and vBond instances, serve as the trust anchor for enterprise networks. An adversary with persistence on a controller can intercept all control traffic and extract data-plane encryption keys, effectively voiding the confidentiality of the entire SD-WAN fabric. The attack often begins with an authentication bypass, such as CVE-2026-20127, allowing the actor to gain an initial foothold. This hunt provides a structured way to find these compromises by looking for the underlying OS modifications required to support the malware framework persistence and evasion techniques.

### The Hypothesis

An adversary exploits a Cisco SD-WAN authentication bypass to establish persistence by modifying runit service scripts and remounting the root filesystem as executable to facilitate malware deployment. The attacker focuses on critical service paths like /etc/sv/sshd/run and /etc/sv/aaamgr/run to ensure the malware survives reboots and maintains high-level access.

### How the hunt flows

The hunt begins in the Linux audit logs (hb_linux_audit) by examining syscall history. It specifically searches for mount syscalls targeting the /rootfs.rw path with the exec option enabled. This is a critical lead because the controller underlying filesystem is normally mounted as non-executable to prevent unauthorized binary execution. The adversary must explicitly remount the filesystem as executable to run their staged payloads and persistence scripts.

If the hunt identifies suspicious remounting activity, it triggers a fan-out phase using file activity logs (hb_file_activity). The first branch of this phase looks for direct writes or modifications to known targets such as /etc/sv/sshd/run, /etc/sv/aaamgr/run, and PAM configuration files like /etc/pam.d/sshd. These locations are where KeyDrift typically embeds its logic to intercept credentials or maintain a persistent backdoor.

- Simultaneously, the hunt performs a fleet-wide stacking analysis of all runit service script modifications. By gathering all modifications to files in the /etc/sv/ directory, the hunt calculates the prevalence of these changes across all controllers. Legitimate maintenance or firmware updates typically appear as identical changes across the entire fleet. In contrast, adversary tampering is usually unique to a small number of compromised controllers, which this query highlights by filtering for low host counts.

In the final triage phase, an automated agent synthesizes the evidence from the remount lead, the targeted file modifications, and the prevalence baseline. This agent determines if the sequence of events aligns with the UAT-11473 staging pattern. If the evidence is sufficient, the hunt prompts the analyst to isolate the controller via a manual action and initiate a forensic review of the modified scripts and the current patch level of the appliance.

### What this hunt cannot see

This hunt has two primary blind spots that practitioners must address. First, the hunt relies entirely on auditd being configured to log the mount syscall. If the SD-WAN controller fleet does not audit syscalls, the initial lead will return zero results, and the hunt will close even if a compromise is active. Second, while the hunt identifies both the remount and the subsequent file writes, the relationship between these events in the logs is temporal rather than causal. An analyst must manually verify that a specific remount event was the prerequisite for the observed service tampering.

### How to run it

This hunt is available as an open hunt.md playbook. You can import it directly into Huntbase or any runtime that supports the hunt.md format for automated execution. The playbook includes parameters for lookback_days to define the search window and target_paths to focus on specific service scripts. It requires access to Linux audit and file activity surfaces from your Cisco SD-WAN controller instances. To ensure coverage, verify that your controllers are shipping syscall-level audit logs to your central telemetry platform.
