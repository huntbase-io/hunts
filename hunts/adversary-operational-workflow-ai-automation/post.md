# Hunting Adversary Jump Boxes Using AI and Automation Infrastructure

### Why this hunt

The Huntress Blog — Rare Look Inside Attacker Operation (https://www.huntress.com/blog/rare-look-inside-attacker-operation) provides a detailed view of a professional threat actor's backend. The adversary does not just compromise a host; they build a workbench. This hunt identifies the specific operational patterns of these workbenches, focusing on how attackers integrate AI and automation into their workflows. Standard detections often trigger on single tools, but this hunt clusters evidence to find the attacker's primary infrastructure.

### The Hypothesis

The adversary operates a dedicated jump box characterized by the installation of multiple security products for research, the use of AI for phishing content generation, and high-volume session maintenance across many compromised identities.

### How the hunt flows

The first phase uses the hb_software_inventory surface to identify hosts with overlapping security agents. While a typical enterprise asset runs a single security product, an adversary often installs multiple competitors like Malwarebytes or Bitdefender. They use these installations to test their malware and evasion techniques in a live environment before deploying them against targets. This scoping step narrows the fleet to potential researcher or adversary systems.

The second phase pivots to DNS activity using hb_dns_activity. We look for resolutions involving AI writing assistants and vulnerability research domains. The adversary uses tools like Toolbaz or DocsBot to automate the creation of convincing phishing lures. They also resolve domains like Censys to conduct reconnaissance. Finding these resolutions clustered on a host that already shows multi-AV installation increases the confidence that the system is an attacker workbench.

The third phase examines authentication patterns via hb_auth_signin. The hunt looks for source IPs that manage a disproportionate number of unique user identities. In an automated phishing operation, the attacker must maintain thousands of sessions. This activity creates a clear anomaly: a single IP address successfully signing into many unique accounts within a short window. We then use hb_network_connection to map these suspicious source IPs back to internal hostnames.

The final phase triages the candidate hosts by checking hb_process_activity. We look for the execution of administrative or persistence tools such as rclone, AnyDesk, or Evilginx. By the time an analyst reaches this stage, they examine a system that has tested multiple AVs, researched phishing with AI, and currently manages high-volume identity sessions.

### Why this is a hunt, not a detection

A single alert on a host resolving a domain like Make.com or an AI writing assistant is prone to high false-positive rates. Legitimate developers and marketers use these tools daily. However, the operational reality of a professional adversary is the cluster of these activities. By treating this as a hunt, we look for the intersection of security tool research, AI content generation, and high-volume session maintenance. This approach allows analysts to identify the specific workbench of an attacker while filtering out the noise of standard business operations.

### Blind spots

This hunt has two primary limitations. First, if the environment lacks correlation between source IPs and hostnames, such as missing DHCP or VPN logs, pinning a sign-in anomaly to a specific internal device is difficult. Second, if the adversary uses DNS-over-HTTPS (DoH), the DNS activity phase will not see the lookups for AI tools. Analysts should supplement this hunt with network flow analysis if they suspect the use of encrypted DNS.

### How to run

This is a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to begin scanning your environment for adversary jump boxes. Because it is a hunt and not a static detection, it requires an analyst to review the clusters of activity. This approach minimizes noise from legitimate administrative jump boxes while ensuring that professional adversary infrastructure has nowhere to hide.
