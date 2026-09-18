# Hunting for ErrTraffic Compromised WordPress Servers and PHP Backdoors

### The Context
Recent research by Sekoia in [Unveiling ErrTraffic: a growing ClickFix malware distribution framework](https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework) highlights how adversaries are weaponizing compromised WordPress sites. These servers are modified to host ClickFix lures—deceptive prompts that trick users into running malicious PowerShell commands. We have drafted this hunt to identify the server-side infrastructure supporting this framework.

### The Hypothesis
Our hypothesis is that an adversary has compromised WordPress servers to install bespoke PHP backdoors. These backdoors serve as stable distribution points for the ErrTraffic framework's ClickFix lures, allowing the attacker to proxy traffic or host malicious scripts like `cf.js` within the `/wp-content/` or `/wp-includes/` hierarchies.

### How the Hunt Flows
The hunt begins with a scoping phase using software inventory data. We focus specifically on systems known to run WordPress. This narrow focus is critical to reducing noise from other web services and ensures we are looking at the right file paths from the start.

Once scoped, the hunt pivots to file activity. We monitor for the creation of new PHP files within sensitive directories such as `/wp-content/plugins/` and `/wp-includes/`. Because legitimate plugins frequently update, we apply a prevalence filter. We stack-count these new filenames across the entire fleet; bespoke backdoors typically appear on a single host or a very small cluster, while genuine updates appear across all WordPress instances of a similar version.

To move from suspicion to high-fidelity evidence, we corroborate these file signals with network telemetry. We look for HTTP request patterns specific to ErrTraffic clusters, such as GET requests to `/cf.js`, `/api/css.js`, or `/api/index.php` that return a 200 OK status. Finding a rare PHP file creation followed by traffic to these endpoints provides a strong signal of active compromise.

### Why This is a Hunt, Not a Detection
Standard detection rules for PHP file creation in WordPress directories are notoriously noisy. Legitimate administrative actions and plugin updates frequently trigger these alerts, leading to SOC fatigue. This is a hunt because it requires fleet-wide prevalence baselining and cross-surface correlation between file system changes and HTTP distribution patterns to distinguish between a routine update and a malicious injection.

### Blind Spots and Limitations
This hunt relies on endpoint file telemetry and web server traffic logs. We cannot see the specific contents of encrypted HTTP POST bodies without TLS decryption, which might hide the exact commands sent to a backdoor. Additionally, without internal WordPress application audit logs, we cannot definitively say whether the initial compromise occurred through a specific vulnerability (T1190) or via stolen administrative credentials.

### How to Run It
This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any other `hunt.md`-aware runtime. The playbook includes the necessary scoping queries and logic to automate the prevalence counting and network correlation steps described above.
