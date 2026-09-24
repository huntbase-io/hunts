# Hunting for VSS Manipulation and Lateral Movement Chains

### Why This Hunt

Administrators and backup agents use Volume Shadow Copy Service (VSS) every day. This creates a significant amount of noise for security teams. As detailed in the Huntress article "How Attackers Abuse VSS, and How Huntress Detects It" (https://www.huntress.com/blog/vss-abuse-explained), adversaries rely on this noise to hide two critical actions: stealing the Active Directory database (ntds.dit) and deleting backups before a ransomware event. A simple detection rule for these utilities often fires on benign maintenance, but a structured hunt provides the context needed to identify an actual intrusion.

### The Hypothesis

An attacker moves laterally into the environment and abuses VSS utilities to either steal the Active Directory database or inhibit system recovery before a ransomware event. They use remote service installation and session enumeration as precursors before manipulating shadow volumes.

### Scoping the Infrastructure

The hunt begins by identifying the high-value targets within the Windows server estate. The first query filters the software inventory for hosts running Microsoft server packages or Active Directory services. This ensures the hunt focuses on the systems where ntds.dit exists or where volume backups are most critical for recovery.

### Tracking Movement and Recon

The next phase runs two parallel searches for precursor activity. One query looks for PsExec service installation or execution, which is a common method for moving to domain controllers. The second query identifies outliers in the use of reconnaissance tools like qwinsta and nslookup. By stack-counting these processes and looking for rare occurrences, the hunt surfaces hosts that deviate from standard administrative hygiene.

### Identifying VSS Abuse

Once the hunt establishes a list of high-risk hosts, it searches for explicit command-line arguments involving vssadmin.exe or diskshadow.exe. It specifically targets commands that create or delete shadow copies. While these commands are native to Windows, their appearance on a host that recently experienced rare lateral movement or session enumeration suggests malicious intent.

### Correlation and Blind Spots

A final correlation step reviews the timeline of these events. If VSS manipulation occurs within the same window as the observed movement, the host is flagged for isolation. This hunt does have blind spots. An attacker who uses direct COM/API calls to the VSS provider instead of the standard CLI utilities will bypass these process-based checks. Additionally, many EDR platforms lack transparency into file access within a mounted shadow volume, meaning the actual theft of a database may remain invisible even if the volume creation is caught.

### How to Run This Hunt

This design is a hunt.md playbook. You can import it directly into Huntbase or any hunt.md-aware runtime. It uses a 14-day lookback period by default and provides parameters to refine the list of process names for your specific environment. After running the automated phases, an analyst should manually verify the lineage from PsExec to VSS commands and check for concurrent file activity near sensitive paths like the NTDS directory.
