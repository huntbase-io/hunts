# Hunting Zimbra CVE-2026-73570 Remote Command Injection and JSP Web Shells

### Why Now

Recent reporting from the [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/) details a critical unauthenticated command injection vulnerability in Zimbra. The flaw resides in the SNMP notification path, where crafted SMTP requests trigger a chain involving swatchdog and snmptrap. Successful exploitation grants attackers code execution as the zimbra user, which they typically use to deploy web shells and harvest credentials.

### The Hypothesis

An adversary exploits CVE-2026-73570 on internet-facing Zimbra servers to execute arbitrary commands via the SNMP path. They then drop JSP web shells in the application webroot to maintain persistent access and exfiltrate mailbox data.

### How the Hunt Flows

The hunt begins by scoping vulnerable hosts. It queries vulnerability management data for any systems with a recorded CVE-2026-73570 finding. This limits the blast radius of subsequent expensive queries. If vulnerability data is unavailable, an analyst can substitute this by searching software inventory for Zimbra versions prior to 10.1.20.

Next, the hunt triages network leads. It examines HTTP logs for the specific User-Agent ZB73570 or connections to known OAST callback domains. These probes represent the initial reconnaissance and exploit verification attempts. A decision gate stops the hunt here if no suspicious probes exist, preventing the execution of heavy host-side queries on benign systems.

If the gate opens, the hunt enters a deep investigation phase. It concurrently examines two high-fidelity sources. First, it traces the process lineage of swatchdog. The query looks for snmptrap spawning shells or network utilities like curl and wget. Second, it baselines JSP files within Zimbra's webroot directories. By calculating the prevalence of these files across the fleet, the hunt highlights rare scripts that likely serve as web shells.

Finally, a triage agent correlates the network probes, the process injection chain, and the rare file creations. This combined evidence provides a high-confidence verdict for each host, allowing the analyst to isolate compromised servers and investigate lateral movement.

### What This Hunt Cannot See

This hunt relies on HTTP telemetry to identify the initial probing. If the environment lacks web server logs or HTTP-aware network monitoring, the lead activity goes unseen, and the hunt may never reach the deep investigation phase. Additionally, if an attacker bypasses the known User-Agent and OAST domains, the triage gate remains closed. Endpoint visibility is also required to see the child processes of snmptrap; without it, unauthenticated execution remains invisible.

### How to Run It

This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. The playbook includes the necessary SQL for scoping and investigation, alongside the decision logic required to navigate the gated flow.
