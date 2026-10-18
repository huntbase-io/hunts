# Atlassian Path Traversal and Administrative Persistence

### Why Now
Rapid7 recently detailed CVE-2026-21589 in their report, [CVE-2026-21589: Critical unauthenticated arbitrary file access in Atlassian products](https://www.rapid7.com/blog/post/etr-cve-2026-21589-critical-unauthenticated-arbitrary-file-access-in-atlassian-products). The vulnerability allows unauthenticated attackers to read sensitive configuration files like crowd.properties using a double-colon traversal sequence. These files often contain plaintext credentials that allow an adversary to take over administrative accounts or create new ones.

### The Hypothesis
An unauthenticated attacker is using double-colon path traversal to read Atlassian configuration files and then creating administrative accounts for persistence.

### How the Hunt Flows
The hunt begins with a lead query against HTTP activity logs. It searches for double-colon sequences and specific paths such as WEB-INF or crowd.properties. This step identifies the initial attempt to exploit the path traversal vulnerability. An analyst or automated agent evaluates these findings to separate automated noise from targeted attempts.

Once a lead is confirmed, the hunt passes through a decision gate. This prevents the hunt from scanning the entire estate unless a credible indicator exists. If the lead is suspicious, the hunt triggers two parallel investigations on the target host.

The first parallel branch inspects the software inventory. It verifies if the host actually runs a vulnerable version of Confluence, Jira, Bitbucket, or Crowd. This confirms if the host was truly susceptible to the exploitation attempt found in the HTTP logs.

The second parallel branch checks for rare additions to administrative groups. It looks for user additions to groups like jira-administrators or confluence-administrators that occurred within the lookback window. The query highlights rare activity, prioritizing changes seen on only one or two hosts in the environment.

A final triage step joins these findings. It looks for a specific pattern: a host that received a traversal request, runs vulnerable software, and shows a new, rare administrative user. If all three signals align, the hunt recommends immediate isolation.

### What the Hunt Cannot See
The hunt relies on the quality of HTTP logging. If an attacker uses double-URL encoding and the logging source does not normalize the URL before writing the log, the pattern match may fail. Additionally, if an attacker creates a local user within an internal Atlassian database that does not emit standard operating system group management logs, the persistence check will miss the account creation.

### How to Run It
This hunt is a hunt.md playbook. It imports into Huntbase or any compatible hunt.md-aware runtime. You can run it manually against specific hosts or as part of a scheduled sweep of your internet-facing Atlassian assets.
