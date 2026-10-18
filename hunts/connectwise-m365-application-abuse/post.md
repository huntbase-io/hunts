# Hunting ConnectWise M365 Vendor Application Abuse

### Why this hunt matters

A recent investigation by Huntress (https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access) details a supply-chain compromise where attackers abused vendor-held credentials for ConnectWise (SkyKick) applications. This is not a simple case of unauthorized access; the adversary uses these trusted identities to pivot into a Global Administrator role and plant long-term persistence across other applications in the tenant. This hunt provides a systematic way to find where these apps are active and whether they performed unauthorized administrative actions.

### The Hypothesis

An adversary exploits compromised ConnectWise (SkyKick) vendor credentials to access M365 tenants, escalates directory privileges by self-assigning high-privilege roles, and persists by adding client secrets to secondary applications.

### How the hunt flows

The hunt starts by scoping the environment. The first query identifies every tenant where the specific ConnectWise Exchange, Teams, or SharePoint applications are active. This limits the search space to at-risk tenants and provides a baseline of normal application activity.

Next, the hunt runs two parallel queries to find initial access. One query searches for password spraying from the reported actor IP address. The second query looks for successful sign-ins by the ConnectWise applications that originate from unusual IP addresses or use rare User-Agent strings. An analyst then triages these signals to confirm if a specific service principal has been hijacked.

The final phase moves to the cloud control plane. The hunt queries the Unified Audit Log for any administrative changes made by the identified applications. Specifically, it looks for the 'Add member to role' operation or the addition of client secrets to other service principals. This step is critical because it identifies the actual damage and persistence mechanisms left behind by the attacker.

### Why this is a hunt, not a detection

A static detection for the known actor IP address is insufficient because attackers rotate their hosting infrastructure frequently. Furthermore, ConnectWise applications perform legitimate administrative tasks daily. A hunt is necessary to differentiate routine vendor maintenance from the specific, sequential pattern of privilege escalation and secondary credential addition described in the breach report.

### Blind spots

This hunt has three primary limitations. First, it requires the Unified Audit Log (UAL) to be active; without these logs, the privilege escalation and persistence phases remain invisible. Second, Microsoft does not log most data-read operations through the Graph API. If an attacker only read mailbox or directory data without changing settings, this hunt will not see that activity. Finally, cloud-to-cloud sign-ins often lack a physical host association, meaning the hunt may identify a compromised tenant without being able to point to a specific infected workstation.

### How to run it

This hunt is a standard hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries against your telemetry. The playbook includes the specific App IDs and actor IPs identified in the initial reporting and is designed to run over a 14-day lookback window.
