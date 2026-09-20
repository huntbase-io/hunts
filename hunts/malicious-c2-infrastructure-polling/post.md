# Malicious C2 Infrastructure Polling for AMOS and NetSupport RAT

### Why this hunt

Huntress recently detailed a phishing campaign (Post-DEF CON Phishing Uses Malicious Google Doc to Deliver Malware — https://www.huntress.com/blog/defcon-phishing-google-doc-malware) that use social engineering to deliver AMOS and NetSupport RAT. The campaign targets conference attendees with lures involving Google Docs and malicious installers. Once a user executes the payload, the malware establishes command and control (C2) to exfiltrate browser data and sensitive notes. This hunt provides a structured method to find these connections in your environment.

### The Hypothesis

An intruder is communicating with AMOS or NetSupport RAT infrastructure through DNS lookups, direct socket connections, or specific HTTP paths, often using processes running from temporary directories.

### How the Hunt Flows

The first query identifies hosts that resolved domains associated with the phishing campaign infrastructure. We look for resolutions to apple-googleapi.com and specific .lat domains. This surface targets the initial contact phase where the malware reaches out to its primary C2 nodes.

Next, we fan out the evidence gathering to include socket-level connections. This query identifies processes establishing direct links to hardcoded IP addresses used for data exfiltration. By looking at the process path, we distinguish legitimate system traffic from malicious tools.

An analyst inspects HTTP traffic for URI patterns used by AMOS loaders. We search for paths like /log or /api/v1/ and specific PHP resources. This check finds activity even when the domain name has changed but the backend server logic remains the same.

The hunt also monitors for outbound network connections originating from user-writable temporary directories. The query flags processes in /tmp or \users\public\ communicating externally. This behavioral lead captures new loaders that use fresh infrastructure but maintain the adversary's staging habits.

We finish the gather phase by checking for unauthorized access to sensitive files. The query identifies non-standard processes—those not belonging to browsers or system notes apps—reading macOS Notes databases and browser cookies. This provides the final evidence needed to confirm successful data theft.

Finally, an analyst reviews the collected rows to assign a per-host verdict. If the review finds correlated network and file activity, the analyst triggers host isolation to stop active exfiltration.

### Blind Spots

Telemetry retention limits the effectiveness of this hunt. If the initial infection and C2 handshake occurred before the 14-day lookback window, the DNS lead might fail to fire. Additionally, without SSL/TLS inspection, the specific URI paths used in HTTPS traffic remain invisible, leaving the analyst to rely on domain-level metadata and IP reputation for the HTTP-based branch.

### How to Run It

This hunt is an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. It functions as a sequence of queries that gate a final manual triage. Because it correlates network signals with host-based file access, an analyst must confirm the verdict for each identified host before proceeding to isolation.
