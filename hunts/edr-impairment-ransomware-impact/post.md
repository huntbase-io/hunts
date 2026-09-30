# Hunting EDR Impairment and Ransomware Impact in SMB Networks

### Why this hunt?

Small and medium businesses face a compressed attack timeline. The recent report "The SMB cybersecurity squeeze: AI agents at work, old attacks in overdrive" (https://www.welivesecurity.com/en/business-security/smb-cybersecurity-squeeze-ai-agents-work-old-attacks-overdrive/) highlights how adversaries combine credential theft with rapid deployment of ransomware. This hunt focuses on the critical moment an attacker moves from persistence to impact. Because SMBs often rely on standard EDR configurations, attackers focus on "Bring Your Own Vulnerable Driver" (BYOVD) techniques to silence those protections before finishing their objective.

### The Hypothesis

An adversary steals credentials from browser stores and attempts to disable security controls using vulnerable drivers before launching a high-volume ransomware or exfiltration attack.

### How the hunt flows

The first phase scopes the environment for suspicious file access. The query identifies instances where a non-browser process, such as a command shell or an unknown binary, reads browser database files like "login data" or "cookies". This pinpointing of credential theft provides the initial list of suspect hosts. By filtering out legitimate browser processes, we reduce the noise from daily user activity while highlighting tools designed to harvest session data.

The hunt then branches into two parallel searches on those suspect hosts. The first check looks for the loading of unsigned or revoked kernel drivers. This is a primary indicator of the BYOVD technique, where an attacker loads a driver with known vulnerabilities to gain kernel-level access and terminate security software processes. The hunt looks specifically for driver signature status and subject names that do not match known, trusted vendors.

The second parallel check focuses on the impact. It baselines file activity to find rare processes performing mass file modifications or renames. Ransomware typically causes a spike in these events as it encrypts user data. By filtering for processes that are rare across the fleet—appearing on three or fewer hosts—we isolate malicious binaries from standard system tools that might touch many files, such as backup software or update agents.

An agent finally weighs these disparate signals together. If a host shows the sequence of credential access followed by driver loading and high-volume file changes, the hunt triggers a verdict. This correlation allows us to distinguish between a developer testing a new driver and an active ransomware deployment. The agent provides a malicious, suspicious, or benign verdict for each host based on the citations from all previous steps.

### What the hunt cannot see

This hunt depends on the EDR ability to report kernel events accurately. If an adversary successfully impairs the security agent before the driver load is logged, the hunt will fail to see the evasion step. This is a common risk when the EDR itself is the target of impairment. Additionally, if an infostealer runs entirely in memory by injecting into a legitimate browser process, the initial file access lead might only attribute the access to the browser itself, causing the hunt to skip that host.

### How to run it

We provide this hunt as an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. The design uses standard SQL queries against the hb_file_activity and hb_kernel_extension_activity surfaces. Users can adjust parameters for the lookback period and the list of targeted browser filenames to match their specific environment and telemetry retention.
