# Hunting PHP Core RCE and Web-to-Shell Staging

### Why hunt for PHP2Shell

Recent research from Elastic Security Labs, titled [php2shell: Assessing Elastic detection coverage relevant to CVE-2026-109618 and CVE-2026-109619](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection), details critical vulnerabilities in the PHP core. These flaws allow unauthenticated attackers to execute arbitrary code. While static detection rules often catch known web shells, this hunt focuses on the broader behavioral footprint of a compromised web worker. We want to find the transition from a web server process to a shell or interpreter, even if the specific exploit payload is new or obfuscated.

### The Hypothesis

An attacker exploits PHP core RCE vulnerabilities to force web server processes to spawn shells or interpreters, which then perform system discovery and payload staging. The adversary moves quickly from the initial request to executing commands like `whoami`, `id`, or `curl` to establish a foothold and prepare for persistence.

### How the Hunt Flows

The hunt begins by identifying vulnerable assets. The first query searches the vulnerability surface to find hosts where the target CVEs remain unpatched. This scoping step ensures analysts prioritize high-risk servers, though the hunt can also run across the entire estate to find undocumented or shadow PHP deployments.

The second phase analyzes early execution in two parallel paths. One path looks for direct shell launches from web server processes like `nginx`, `apache2`, or `php-fpm`. The second path performs a frequency analysis of all children spawned by web processes. By stack-counting these relationships across the fleet, the hunt highlights rare pivots—such as a single web server launching an unusual binary—that traditional rules might miss due to their low volume or lack of a known-bad signature.

An analyst then triages these execution hits. They evaluate the command lines to distinguish legitimate administrative scripts from malicious activity. Once a suspicious host is identified, the hunt searches for follow-on staging behavior. This query looks for discovery tools and downloaders like `wget`, `python`, or `hostname` on the targeted systems. The hunt concludes by correlating the initial shell launch with these staging actions to provide a final verdict.

### Why this is a hunt, not a detection

Detection rules for web-to-shell activity often generate high noise in environments where administrators run maintenance scripts or backups directly through web worker contexts. This hunt uses fleet-wide prevalence and human triage to separate that administrative noise from an actual exploit. It looks for the convergence of a vulnerability, a rare process pivot, and follow-on discovery, rather than just a single process event.

### Blind Spots and Limitations

This hunt relies heavily on process telemetry. If a web server is not enrolled in endpoint monitoring, it remains a complete blind spot. Additionally, sophisticated attackers might execute code entirely within the PHP worker process memory without spawning a child process. Such memory-only exploitation is invisible to the process-launch telemetry used here and requires specialized engine-level tracing to detect.

### How to Run This Hunt

This hunt is provided as an open `hunt.md` playbook. You can import it into Huntbase or any `hunt.md`-aware runtime to execute the queries and manage the triage steps. The playbook includes built-in parameters for lookback windows and host scoping to help you tailor the search to your environment.
