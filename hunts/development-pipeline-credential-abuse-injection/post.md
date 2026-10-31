# Hunting for Developer Credential Abuse and Repository Code Injection

### Why this hunt

The ESET APT Activity Report Q2 2026–Q3 2026 details how North Korea-aligned threat actors target developer environments. These groups compromise identity providers or harvest local credentials to gain access to private source code. Once inside, they move quickly to extract repository secrets and inject malicious code into the supply chain.

### The Hypothesis

An adversary has compromised developer credentials to harvest sensitive repository secrets and inject malicious code into private source code repositories, bypassing standard CI/CD protections.

### Identifying the Push

The hunt begins by examining the GitHub audit log for push events and repository updates. This first query provides a broad list of activity across critical repositories. Because developers push code every day, this step produces many results. The hunt filters these by repository importance and lookback periods to establish a working set of actors and modified resources.

### Correlating Secrets and Identity

The second phase runs two queries in parallel to find evidence of account misuse. One query calculates the prevalence of secret enumeration. It stacks API calls like get secret or list keys to find developers who rarely perform these actions. A legitimate developer might occasionally check a secret, but an adversary harvests them systematically. Simultaneously, the hunt checks authentication telemetry from Entra ID, Okta, or GitHub for high-risk sign-ins or failed MFA attempts associated with the same accounts.

### Triage and Mitigation

An analyst weighs the combined evidence. A developer who pushed code shortly after a high-risk login and a rare secret enumeration session represents a confirmed compromise. If the verdict is malicious, the playbook directs the operator to revoke all active sessions and Personal Access Tokens for that account. Finally, the hunt concludes with a manual review of the specific code diffs, as audit logs do not capture the actual code changes.

### Blind Spots

This hunt relies on audit logs, which have inherent limits. The GitHub API logs the fact that a push occurred but does not include the file diff itself. An analyst must manually inspect the repository to see what code changed. Additionally, sophisticated session hijacking may appear as a successful login. If an actor steals a valid session cookie, the authentication logs may not show a high-risk event or an MFA failure.

### How to Run the Hunt

This hunt is an open hunt.md playbook. You can import it directly into Huntbase or any runtime that supports the hunt.md format. It uses standard SQL queries against common cloud and identity surfaces. Focus the initial parameters on your most sensitive production repositories to reduce the initial triage volume.
