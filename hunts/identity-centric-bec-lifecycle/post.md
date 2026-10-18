# Hunting the Identity-Centric Business Email Compromise Lifecycle

### Why Now

Business Email Compromise remains a primary driver of financial loss across organizations. While many teams focus on the initial phishing email, the actual impact happens after the identity is lost. The Huntress article [Business Email Compromise (BEC) Attacks: How to Stop Them](https://www.huntress.com/blog/what-is-business-email-compromise-bec) outlines how attackers move from proxy-based logins to internal lateral movement and financial redirection. This hunt implements that research as a structured playbook.

### The Hypothesis

An adversary has hijacked an identity through an Adversary-in-the-Middle (AiTM) proxy or by exploiting a public-facing vulnerability. They then manipulate mailbox rules to hide fraudulent communication and spread malicious internal attachments to peers.

### How the Hunt Flows

The hunt begins by identifying the attack surface. A scoping query finds internet-facing devices with high-severity vulnerabilities. These assets often serve as the initial point of entry for attackers seeking to gain a foothold in the network before moving to identity-based attacks.

In the second phase, the hunt gathers evidence of initial access. Two queries run in parallel: one identifies logins originating from known anonymizing proxies, and another monitors endpoint HTTP traffic for communication with known AiTM phishing domains. An automated agent then triages these signals to determine which users show a high likelihood of account takeover.

The third phase investigates persistence and internal spread. One query looks for new or modified M365 mailbox rules, specifically those that move mail to the RSS Feeds or Deleted Items folders to hide attacker activity. A second query monitors common email clients like Outlook for suspicious child processes, such as PowerShell or CMD, which indicate a malicious attachment has been executed.

A final synthesis step brings all findings together. An analyst confirms the verdict by correlating the rare proxy logins with subsequent mailbox manipulation or endpoint execution. This sequence differentiates a compromised account from an administrator performing routine maintenance.

### What the Hunt Cannot See

This hunt has two primary blind spots. First, cloud audit latency in M365 means rule changes may not appear in the telemetry immediately after they occur. Attackers can manipulate rules and delete evidence within minutes, potentially escaping the hunt window. Second, without full TLS inspection, the HTTP traffic search only sees the destination hostname. If an attacker uses a legitimate compromised service for phishing, the specific malicious URI remains hidden.

### How to Run It

This hunt is provided as an open hunt.md playbook. It defines the logic, parameters, and investigative steps needed to assess your environment. You can import this playbook directly into Huntbase or any hunt.md-aware runtime to execute the queries across your cloud and endpoint telemetry. Because this focuses on correlation rather than single events, it works best when run against at least 14 days of historical data.
