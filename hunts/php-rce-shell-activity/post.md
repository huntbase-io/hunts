# Hunting for PHP Remote Code Execution and Shell Activity

### Why This Hunt

The CISA advisory, [Critical Vulnerabilities in PHP Require Immediate Patching](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching), details flaws that allow unauthenticated remote code execution. Because PHP is a foundational component for many web applications and is often embedded in other software, these vulnerabilities present a high risk for unauthorized access. This hunt provides a systematic way to verify if an adversary has weaponized these flaws within your environment.

### The Hypothesis

An adversary exploits the php2shell vulnerabilities (CVE-2026-109618 or CVE-2026-109619) to execute unauthenticated code. This exploitation manifests as PHP worker processes spawning interactive shells or utility tools to retrieve secondary payloads. The adversary aims to establish a foothold by moving from a web-based exploit to operating system commands.

### How the Hunt Flows

The hunt begins by establishing the vulnerable surface. It queries the software inventory for any hosts running PHP versions below the security fix thresholds. This provides a focused list of systems where exploitation is most likely. Because vulnerability scanners sometimes miss embedded PHP installations, the hunt uses raw package data to ensure better coverage.

Next, the hunt moves to behavioral analysis of the scoped hosts. It examines the child processes of PHP handlers such as php-fpm, php-cgi, or php.exe. By stack-counting these children across the environment, it identifies rare binaries that appear on only a few hosts. This baseline helps isolate custom scripts or malicious binaries that differ from standard web server behavior.

In the third phase, the hunt looks for high-confidence indicators of exploitation. It searches for specific shells and downloaders like bash, powershell.exe, curl, or certutil.exe being launched directly by PHP workers. This specific pattern is highly unusual for legitimate web applications and is a primary signal for a successful compromise.

Finally, an agent reviews the findings. It correlates the presence of vulnerable software with the observed process behavior to provide a host-by-host verdict. This final check ensures that legitimate administrator maintenance is not confused with active exploitation.

### What This Hunt Cannot See

This hunt has two primary blind spots. First, it does not have visibility into the HTTP request body. It cannot see the exploit payload itself as it arrives at the server; it only observes the resulting process activity. Second, the scoping relies on the freshness of the software inventory. If a server is unmanaged or has not reported inventory data recently, the hunt might not include it in the initial scope.

### How to Run It

This hunt is provided as a `hunt.md` playbook. It is a portable, machine-readable document that describes the logic and queries. You can import this file into Huntbase or any hunt.md-aware runtime to execute the queries across your estate. The playbook includes parameters for lookback periods and specific suspicious tool names to tailor the analysis to your environment.
