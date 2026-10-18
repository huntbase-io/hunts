# Hunting Identity Exposure and Credential Leaks in Infostealer Logs

### Why This Hunt Matters

High-profile intrusions, such as the 2024 Snowflake and CircleCI breaches, demonstrate that the perimeter now begins at the employee's home browser. Adversaries do not always need to exploit a zero-day when they can simply buy valid credentials. In the post [Introducing Sekoia Digital Risk: Track Identity-Led Breaches](https://www.sekoia.com/blog/with-sekoia-intelligence-we-gave-you-half-the-picture-heres-the-other-half), Sekoia highlights the necessity of monitoring the criminal "stealer" economy to complete the security picture.

### The Hypothesis

Adversaries use corporate credentials harvested from unmanaged personal devices by infostealers to bypass authentication controls and gain initial access to cloud resources. This bypass occurs because the stolen data often includes session cookies or valid MFA factors that allow the attacker to impersonate a legitimate user from a new location.

### How the Hunt Flows

The first phase identifies active corporate workstations. The query scans authentication logs to build a list of hostnames where corporate domain logons occur. This scoping ensures the hunt focuses on active identities rather than stale accounts.

Next, the hunt branches into two parallel paths. The first path establishes a behavioral baseline by stack-counting source IPs per user. It identifies rare authentication sources that deviate from the user's normal pattern. Simultaneously, the second path performs an enrichment lookup against Hudson Rock. This check identifies if corporate identities for the target domain have recently appeared in indexed stealer logs from families like RedLine or Lumma.

In the triage phase, an analyst or automated agent weighs the intersection of these two paths. The hunt flags users who show both external exposure in criminal markets and internal behavioral anomalies, such as a login from an IP never seen before in the environment. If the correlation holds, the hunt provides instructions to revoke active sessions and force a credential reset.

### What the Hunt Cannot See

This hunt has two primary blind spots. First, it lacks visibility into the unmanaged endpoint. We can see the result of a credential theft, but we cannot see the initial infection on the user's personal machine or what other personal data was stolen. Second, there is a latency gap. A credential might be stolen and used by an adversary before it is indexed by external monitoring platforms. During this window, the hunt cannot rely on enrichment data to flag the identity.

### How to Run the Hunt

This hunt is provided as an open `hunt.md` playbook. It is designed to be portable and imports directly into Huntbase or any runtime that supports the hunt.md standard. Because it relies on both internal logs and external API lookups, ensure your environment has the necessary integrations for authentication telemetry and Hudson Rock data.
