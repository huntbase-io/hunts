# Hunting Lateral Movement and NTLM Relay in Spring Ring Campaigns

### Why This Hunt

Recent analysis by Unit 42 in [Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams](https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/) detailed an actor using voice phishing to gain an initial foothold. However, the risk to the organization escalates during the lateral movement phase. This hunt focuses on the specific tools and techniques used to move from a compromised workstation toward a domain controller using NTLM relay and PetitPotam-style coercion.

Traditional detections often struggle with this phase because they rely on individual command-line alerts (like `net group /dom`) that are frequently used by legitimate administrators. By treating this as a hunt, we can correlate specific tool paths with network behavior and authentication anomalies that would otherwise be lost in the noise.

### The Hypothesis

We hypothesize that an attacker is operating out of a non-standard Python environment staged in a user-writable directory (like `ProgramData`) to execute discovery scripts. Following this, they will use native Windows utilities to enumerate domain groups and initiate outbound SMB connections to internal servers to facilitate NTLM relay attacks.

### How the Hunt Flows

The hunt begins by scoping for the specific Python execution environment identified in the Spring Ring report. We look for binary executions originating from paths like `c:\programdata\integritydata\python.exe`. This provides a high-fidelity starting point for identifying potentially compromised hosts.

Once a host of interest is identified, we search for domain and group enumeration attempts. This phase focuses on the execution of commands like `whoami /groups` or `net group /dom`. While common in administrative scripts, their appearance on an endpoint already flagged for unauthorized software execution increases the severity significantly.

We then move to a network-level baseline, stack-counting outbound SMB traffic (port 445). The goal is to identify rare processes that are initiating internal connections. Most workstations have a predictable set of processes that use SMB; finding an unauthorized Python binary or a rare utility attempting to reach out to multiple internal IPs is a strong indicator of scanning or relay attempts.

Finally, we enrich these findings with NTLM authentication logs. We look for high counts of sign-in failures between internal hosts. This correlation helps distinguish between simple network scanning and an active attempt to coerce NTLM authentication for relay purposes.

### What This Hunt Cannot See

This hunt has two primary blind spots. First, without logs from the Domain Controllers themselves, we cannot confirm if an NTLM relay was successful; we only see the attempt from the source workstation. Second, general SMB port 445 traffic indicates a connection but does not reveal the specific RPC calls used. If an attacker uses a different coercion method that blends in with standard traffic, additional deep packet inspection or Sysmon RPC filtering would be required for full visibility.

### How to Run It

This hunt is packaged as a `hunt.md` playbook. It is designed to be imported into any `hunt.md`-aware runtime, such as Huntbase. The playbook uses structured SQL queries to interact with process, network, and authentication logs. Because it relies on baselining, we recommend running this over a 14-day lookback period to ensure legitimate administrative patterns are properly understood before triaging the results.
