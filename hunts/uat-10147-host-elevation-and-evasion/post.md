# Hunting UAT-10147 Host Elevation and Evasion Tradecraft

### Why now

Recent reporting from Cisco Talos in UAT-10147 integrates agentic AI into post-compromise operations (https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/) describes an adversary using automated playbooks to scale their post-exploitation tasks. While much of the initial noise occurs at the network and web shell layer, the adversary quickly moves to secure the host. They use standardized batch scripts to download tools, elevate privileges, and modify the local environment to avoid detection. This hunt focuses on those host-side artifacts that appear once the intruder moves past the initial web exploit.

### The Hypothesis

An adversary executes automated staging scripts to deploy privilege escalation tools and blind security software on compromised web servers. They rely on the speed of these scripts to establish a foothold and clear the path for persistent access before an analyst can intervene.

### How the hunt flows

The hunt begins by scoping the environment. The first query identifies hosts running web server software like IIS, Nacos, or Nginx. This limits the search to the surfaces most likely to host the initial exploit. By narrowing the scope to these specific workloads, the hunt reduces noise and focuses on the high-risk perimeter.

Once the scope is set, the hunt runs two searches in parallel. One search looks for specific filenames used by UAT-10147 to stage their tools, such as back.bat and user.bat. The other search monitors for rare process executions involving privilege escalation tools like EfsPotato or exploits for CVE-2022-0995. These tools are often the first things an intruder runs after gaining a low-privilege shell.

The next phase pivots into defense evasion. The adversary modifies the Windows Registry to add specific IIS directories to the Windows Defender exclusion list. This ensures that their malicious modules remain undetected during routine scans. The hunt specifically checks for registry writes targeting these exclusion paths, which are highly unusual in standard server operations.

Finally, the hunt looks for persistence and discovery. It searches for deceptive scheduled tasks, such as 'Google Chrome Start', which the adversary uses to maintain access. It also looks for the use of appcmd to enumerate IIS site configurations. An analyst then correlates these disparate events—the script drop, the elevation attempt, the registry change, and the new task—to confirm a successful compromise.

### What the hunt cannot see

This hunt depends on endpoint telemetry. If a web server does not have EDR coverage, the adversary can execute their elevation chain without generating process logs. While registry and file artifacts might remain, the specific execution context is lost. Additionally, if the adversary renames their staging scripts or uses environment variable expansion to obfuscate command strings, simple filename matching will fail. The hunt assumes the adversary follows the observed pattern of using standardized filenames in their automation.

### How to run it

This hunt is provided as an open hunt.md playbook. It defines the logic and queries required to find these artifacts across your environment. You can import this playbook into Huntbase or any runtime that supports the hunt.md format to execute the steps against your telemetry providers. Because this is a hunt, it focuses on connecting multiple low-fidelity signals into a high-confidence verdict rather than relying on a single detection rule.
