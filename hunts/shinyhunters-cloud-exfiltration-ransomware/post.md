# Hunting ShinyHunters Cloud Exfiltration and Ransomware

### Why now

ShinyHunters remains a persistent threat to cloud-first organizations, often stealing hundreds of millions of records for extortion. A recent report by Sekoia, [Gotta Breach 'Em All! The Journey Of ShinyHunters](https://www.sekoia.com/blog/gotta-breach-em-all-the-journey-of-shinyhunters), details their evolution from simple data theft to more aggressive extortion tactics. This hunt focuses on the overlap between their cloud-native collection and the endpoint impact that follows.

### The hypothesis

An adversary uses compromised credentials or OAuth tokens to exfiltrate bulk S3 data and GitHub repositories before deploying ransomware for extortion. This actor does not just steal data; they disrupt operations to increase their influence over the victim and use the threat of encryption during negotiations.

### How the hunt flows

The hunt begins in the cloud. The first query searches AWS CloudTrail logs for unusual patterns of data retrieval. It isolates cloud identities performing a high volume of GetObject calls. The query groups this activity by user and source IP to highlight anomalous bulk access that exceeds standard administrative baselines. High-volume access from a rare IP address provides the first lead.

Once a suspicious identity emerges, the hunt pivots to GitHub audit logs. The adversary often clones private repositories to identify secrets or intellectual property. The query looks for users interacting with an unusual number of repository blobs or performing bulk clones. This step helps confirm the breadth of the exfiltration attempt and identifies which identities are compromised.

In the final technical phase, the hunt moves to the endpoint. ShinyHunters has recently adopted ransomware-like behavior to finalize their extortion. The query scans endpoint file activity for high-frequency rename events. It filters for processes that modify hundreds of files in a short window, which is a common indicator of encryption. By correlating these endpoint renames with the initial cloud exfiltration leads, an analyst can link the entire campaign together.

Finally, a triage step synthesizes these findings. An analyst or agent reviews the timestamps and source IPs across the cloud and endpoint surfaces. This cross-surface correlation is necessary because individual S3 or GitHub alerts are often too noisy to stand alone. Linking bulk theft to local encryption provides the context required for a high-confidence verdict.

### What the hunt cannot see

Visibility depends heavily on log configuration. If AWS CloudTrail Data Events are not enabled, the hunt only sees management activity like ListBucket rather than the specific S3 objects retrieved. Similarly, standard GitHub logs may not capture the specific git-clone command if it occurs via certain OAuth application flows. Without these granular logs, an analyst can see that an identity was active but cannot confirm exactly what data was stolen.

### How to run it

This hunt is an open-source hunt.md playbook. It defines the logic, parameters, and queries in a structured format that you can import into Huntbase or any runtime that supports the hunt.md standard. Because it uses common surfaces like CloudTrail and EDR file activity, you can adapt the SQL queries to your specific data lake if needed.
