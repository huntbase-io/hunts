# Hunting PaperCut NG/MF Auth Bypass to RCE and Ransomware

### Why now

Rapid7 recently detailed a critical exploit chain in their article, PaperCut NG/MF Critical Zero-Day Exploited in the Wild (https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild). The vulnerability involves two specific CVEs that allow an unauthenticated attacker to bypass security filters, reconfigure internal application settings, and achieve remote code execution. Because PaperCut servers often sit in the middle of corporate networks with significant privileges, they have become a primary target for ransomware groups seeking a foothold.

### The Hypothesis

An attacker has exploited the PaperCut NG/MF authentication bypass vulnerabilities to reconfigure external database lookups and execute arbitrary code. This access leads to secondary impacts, such as application log tampering to hide the intrusion or high-volume file encryption characteristic of ransomware activity.

### How the Hunt Flows

The hunt begins with a scoping phase using software inventory surfaces. We identify every host running the PaperCut NG or MF application. This narrows the behavioral search to relevant servers and reduces noise from unrelated web traffic or process activity across the fleet.

In the second phase, we look for signs of the initial exploit. The hunt queries HTTP activity for specific Apache Tapestry URI patterns targeting the ConfigEditor or UserList components through the application's error or exception pages. Simultaneously, we look for common shell interpreters—such as cmd.exe, bash, or powershell—spawning directly from the PaperCut application process. Finding both a bypass URI and a subsequent shell on the same host provides a high-confidence indicator of compromise.

Once we establish execution, the hunt pivots to investigate impact. We search file activity logs for two distinct behaviors: the deletion or modification of the PaperCut server.log file and instances where a PaperCut-linked process modifies more than 100 distinct files in a short window. This volume of activity is a behavioral outlier for a print server and suggests active ransomware encryption.

Finally, the hunt provides a path for remediation. If the triage confirms the full attack chain, the playbook facilitates host isolation to stop encryption and lateral movement before guiding an analyst through patching to the latest secure vendor release.

### Blind Spots

This hunt has two primary blind spots. First, if the PaperCut server uses HTTPS and the environment lacks TLS decryption or server-side HTTP logging, the specific URI query parameters used for the bypass will remain invisible to network-based queries. In these cases, the hunt relies entirely on the behavioral process signals. Second, the initial JavaScript execution happens within the Java Virtual Machine via the Nashorn engine. We see the shells spawned by this engine, but the in-memory execution of the script itself is not captured by standard process logs.

### How to Run it

This hunt is provided as a hunt.md playbook. It is a machine-readable format that you can import into Huntbase or any hunt.md-aware runtime. The playbook contains the logic to automate the correlation between the HTTP requests, the shell execution, and the file-system impact, allowing you to move from a zero-day report to a confirmed environment verdict in minutes.
