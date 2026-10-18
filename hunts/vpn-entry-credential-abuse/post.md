# Hunting VPN Entry Points and Internal Credential Abuse

### Why this hunt

Unit 42 recently detailed an intrusion in "The Noise Inside the Network: How an Unsophisticated Attack Exposed a Third-Party Risk" (https://unit42.paloaltonetworks.com/noise-inside-network-third-party-risk/). The report highlights how attackers exploit weak perimeter security on third-party access points. This hunt replicates that detection path. We look for the moment an adversary enters via a VPN and immediately begins testing credentials to move laterally.

### Hypothesis

An attacker gains initial access through a misconfigured VPN gateway lacking multi-factor authentication. They then brute-force administrative accounts across internal systems to escalate privileges and establish persistence.

### How the hunt flows

The scoping phase targets the perimeter. The first query identifies successful sign-ins to VPN services where multi-factor authentication was either disabled or not reported. This narrows the focus to high-risk sessions that bypass standard security controls.

The second phase fans out to find evidence of lateral risk. One query monitors for internal brute-force patterns. It identifies internal source IPs attempting to guess passwords for multiple administrative accounts, such as root or service accounts. Simultaneously, the hunt baselines account lifecycle changes. It looks for rare password resets or account creations that deviate from normal administrative behavior.

The triage phase correlates these signals. An agent evaluates the coincidence of the MFA-less VPN entry, the volume of internal authentication failures, and any anomalous account modifications. This determines if the activity indicates a successful intrusion or routine network noise.

### What this hunt cannot see

This hunt has two primary blind spots. First, it depends on VPN gateway logs residing in the central data lake. If an attacker enters through an unmonitored or shadow gateway, the scoping step will fail. Second, the hunt relies on the accuracy of MFA reporting. If a provider always reports MFA status as NULL or if the ingestion parser does not correctly map the field, the hunt will generate excessive false positives.

### Why this is a hunt

We designed this as a hunt because a single detection rule typically focuses on one signal, such as a brute-force attempt. That approach lacks context. This hunt correlates the entry point with the subsequent volume of failures and the baseline of account changes. By looking at the identity plane holistically, we distinguish between a noisy scanner and a specific adversary following a perimeter breach.

### How to run it

This hunt is an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. It uses parameters for lookback periods and administrative account patterns to help you tune the results for your environment.
