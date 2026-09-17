# Hunting for Local Credential Harvesting in LSASS and Browser Profiles

### Why This Hunt Matters

Credential harvesting remains a critical precursor to lateral movement and full account takeover. As detailed in the Huntress article [Credential Theft: Expanding Your Reach](https://www.huntress.com/blog/credential-theft-expanding-your-reach), attackers are increasingly moving beyond simple phishing to automated tools that extract stored credentials directly from the endpoint. This hunt provides a structured way to look for those footprints before they result in a breach.

### The Hypothesis

We hypothesize that an intruder or infostealer is operating on an endpoint and attempting to extract credentials by either dumping the LSASS process or accessing browser profile databases (such as Chrome's 'Login Data' or 'Cookies' files). These actions often occur shortly before data is exfiltrated to a rare external destination.

### How the Hunt Flows

The hunt begins with a scoping phase on the software inventory surface. We identify endpoints that have common web browsers installed, as these systems house the credential stores most frequently targeted by automated harvesting malware. This focuses our resources on the systems with the highest risk of identity-data exposure.

Next, we pivot to process activity to look for native system tools used in non-standard ways. Specifically, we search for instances of `comsvcs.dll` being used for minidumps or `procdump` targeting the LSASS process. These are common methods for obtaining password hashes or plaintext credentials from memory, often performed by actors who wish to avoid bringing custom malware onto the system.

In parallel, we examine file activity to detect non-browser processes accessing sensitive browser database files. We look for bulk read operations on files like `Login Data`, `Cookies`, or `logins.json` by processes other than `chrome.exe`, `msedge.exe`, or `firefox.exe`. This helps isolate potential infostealers that are programmatically scraping these databases for session tokens and passwords.

Finally, we correlate these findings with outbound network telemetry. By identifying rare outbound connections initiated by the same non-browser processes that accessed the credential files, we can distinguish between a suspicious file access event and an actual exfiltration attempt. This multi-surface correlation is what differentiates this hunt from a simple detection rule.

### What This Hunt Cannot See

This hunt has two primary blind spots. First, it relies on endpoint telemetry; any system without a reporting agent remains a visibility gap. Second, malware using direct syscalls to read LSASS memory may bypass command-line monitoring. Such activity is usually only visible through kernel-level handle auditing, which is outside the scope of this particular playbook.

### How to Run the Hunt

This hunt is provided as an open `hunt.md` playbook. You can import it into any runtime that supports the `hunt.md` standard, such as Huntbase. Once imported, you can configure the lookback parameters—defaulted to 14 days—and execute the queries against your environment to start triaging potential harvesting activity.
