# Hunting for persistence after suspicious remote access logons

### Why this hunt matters

Monitoring every authentication event for a large fleet creates too much noise for a standard detection rule. However, ignoring geographic anomalies risks missing the first stage of an intrusion. In their analysis of multi-tenant SOC challenges, [Sekoia](https://www.sekoia.com/blog/why-multi-tenant-socs-need-multi-level-agents) discusses how visibility gaps between different agent levels can leave defenders blind. This hunt addresses that gap by correlating authentication logs with endpoint-level persistence mechanisms.

### The hypothesis

An attacker gains access via an external remote service and establishes persistence using a scheduled task. This task either executes a remote administration tool (RAT) or a malicious script to maintain their hold on the environment.

### How the hunt flows

The hunt starts with a low-cost lead query on the `hb_auth_signin` surface. It filters for successful logons originating from countries outside of a permitted list or sessions using known VPN protocols. Because remote work makes geographic filtering imperfect, an agent or analyst first reviews these leads to confirm if the session represents a legitimate risk before triggering deeper, more resource-intensive queries.

Once a lead is confirmed, the hunt fans out to search for evidence of persistence on the affected hosts. One branch scans `hb_scheduled_job` for newly created tasks that call script interpreters like PowerShell, cmd.exe, or cscript. These are common vehicles for attackers to download second-stage payloads.

Simultaneously, the hunt checks the `hb_process_activity` surface for the execution of remote administration tools like AnyDesk or ScreenConnect. To reduce noise, the query calculates fleet-wide prevalence. It ignores tools used across the entire company and flags those appearing on three or fewer hosts. This focuses the investigation on tools that are likely attacker-installed rather than IT-standardized.

Finally, a triage step correlates the initial suspicious logon with the presence of new tasks or rare tools on the same host. If the timing and host match, the hunt provides a high-confidence verdict to isolate the host and rotate credentials.

### Blind spots and limitations

This hunt relies heavily on IP-to-location enrichment. If an attacker uses a proxy or a VPN that originates from a permitted country, the initial lead query will not flag the session. We also assume the endpoint agent is healthy. If an intruder compromises a server where the agent is disabled or failing to report scheduled job telemetry, the persistence will remain invisible.

### How to run it

This hunt is available as a `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. Before running, customize the `permitted_countries` list to match your organization's footprint to ensure the lead query remains effective and manageable.
