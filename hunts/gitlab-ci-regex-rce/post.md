# Hunting for Unauthenticated RCE in Self-Managed GitLab (CVE-2026-97229)

### Why now

Rapid7 recently published a report on CVE-2026-97229 (https://www.rapid7.com/blog/post/etr-cve-2026-97229-critical-unauthenticated-remote-code-execution-in-gitlab), detailing a CVSS 10.0 vulnerability in self-managed GitLab Community and Enterprise editions. This flaw resides in the Ruby Onigmo regex engine used during CI/CD configuration parsing. An unauthenticated attacker can trigger an integer overflow by submitting a crafted .gitlab-ci.yml file, leading to remote code execution as the git user.

### Hypothesis

An adversary exploits CVE-2026-97229 by planting a malicious .gitlab-ci.yml file in a repository. This action causes an integer overflow when the GitLab worker processes the configuration, allowing the attacker to execute arbitrary shell commands with the privileges of the git user account.

### How the hunt flows

The hunt begins with a scoping phase using software inventory telemetry. It identifies every self-managed GitLab instance running the affected 19.2, 19.3, or 19.4 branches. This prevents the hunt from processing telemetry for patched or unrelated systems, ensuring the remaining queries focus only on vulnerable infrastructure.

After identifying targets, the hunt searches for delivery evidence through two parallel paths. The first query monitors file activity for writes to .gitlab-ci.yml files, while the second examines web traffic for unauthenticated project creation or IDE session initialization. These queries establish a timeline of configuration changes that could deliver the exploit payload.

The execution phase pivots to process telemetry to find signs of a successful overflow. It looks for rare shell spawns or network utility executions, such as bash, python, or curl, originating from GitLab worker processes like Sidekiq, Ruby, or Bundle. The query uses stack-counting across the estate to highlight commands that appear on three or fewer hosts, filtering out common developer hooks or maintenance tasks.

Finally, an automated agent reviews the findings from all previous steps. It correlates the presence of a vulnerable version with recent delivery indicators and anomalous process behavior. This multi-stage approach ensures that a verdict of malicious activity is based on a complete exploit chain rather than an isolated, potentially benign event.

### What the hunt cannot see

This hunt requires endpoint telemetry from an agent installed on the GitLab host. If a server is not enrolled in process and file monitoring, the hunt cannot observe the execution or delivery phases. Additionally, the telemetry used here focuses on file paths and process command lines; it does not include the content of the .gitlab-ci.yml file itself. An analyst must manually inspect the repository contents if the hunt flags a suspicious configuration write to confirm the presence of the malicious regex.

### How to run it

This hunt is a hunt.md playbook. You can import it into Huntbase or any runtime that supports the open hunt.md standard. By default, the playbook uses a 14-day lookback period to cover the window following the vulnerability disclosure, though you can adjust this parameter to match your specific log retention policies or suspected compromise window.
