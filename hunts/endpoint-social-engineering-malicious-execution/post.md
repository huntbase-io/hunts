# Hunting Social Engineering and Manual Execution via ClickFix

### Why now
The [Huntress Tragic Quadrant: Top Cyber Threats Wrecking Businesses](https://www.huntress.com/blog/huntress-tragic-quadrant-cyber-threats) identifies social engineering and user-driven execution as persistent, high-prevalence threats. Attackers increasingly use AI-generated lures and ClickFix techniques to bypass technical controls by convincing users to manually paste commands into the Windows Run box. This bypasses many standard email filters and browser-based protections by placing the burden of execution on the end user.

### The hypothesis
An attacker uses AI-tuned phishing lures or ClickFix social engineering to trick a user into executing shell commands from the Run box, eventually deploying rogue RMM tools or infostealers.

### How the hunt flows
The hunt begins by identifying Windows hosts within the `hb_software_inventory` to establish a target scope. This scoping phase ensures we focus on endpoints where manual shell execution is most impactful and helps filter out non-Windows systems that do not use the explorer.exe shell.

Next, the hunt runs two parallel checks to identify the point of infection. The first query examines `hb_http_activity` for outbound traffic to AI platforms or known lure domains like Railway and Claude.ai. The second query monitors `hb_process_activity` for shell processes where the parent is `explorer.exe`. This specific parent-child relationship is a direct indicator of a user pasting commands into the Run box or a folder address bar.

A triage phase uses an agent to evaluate these early-stage signals. The agent confirms if the lure traffic and shell execution happen within a close temporal window. This step filters out noise from users who might use the Run box for legitimate tasks, focusing the hunt on hosts with high-confidence compromise indicators.

After confirming the initial access, the hunt moves into evidence gathering for persistence and impact. It performs a stack-count on `hb_process_activity` to find RMM tools like AnyDesk or ScreenConnect that appear on three or fewer hosts. Tools found fleet-wide are typically sanctioned; rare ones suggest an attacker-installed instance used for persistence. Simultaneously, it audits `hb_file_activity` for unknown processes reading browser Login Data or Cookies, which is a signature of infostealers like LummaC2.

Finally, the hunt synthesizes these signals. By linking the initial web redirect to the manual execution and subsequent file theft or RMM deployment, we confirm a complete intrusion chain rather than treating each event as an isolated anomaly. An analyst then confirms the final verdict and isolates affected hosts.

### What the hunt cannot see
This hunt has two primary blind spots. First, if a user clicks a redirect that bypasses endpoint HTTP logging—such as an internal browser redirect or a link that does not trigger a new request to a tracked domain—the `hb_http_activity` surface may stay silent. Second, command line truncation in process telemetry can hide indicators. If the attacker uses a very long, encoded PowerShell string, we might lose the iex or -enc flags required for high-fidelity detection.

### How to run it
This hunt is available as an open `hunt.md` playbook. You can import it directly into Huntbase or any runtime that supports the hunt.md format to begin scanning your estate for ClickFix activity. The hunt is designed to be run periodically to catch new lures as they emerge.
