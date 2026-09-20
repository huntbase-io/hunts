# Hunting for ErrTraffic WordPress Infrastructure and Backdoors

### Why hunt for ErrTraffic

Sekoia recently published research titled [Unveiling ErrTraffic: inside a growing ClickFix malware distribution framework](https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework). The report describes a sophisticated ecosystem where attackers compromise legitimate WordPress sites to host ClickFix lures. These lures trick users into running malicious code, often leading to infostealer infections. While many detections focus on the final payload, this hunt looks for the engine: the compromised WordPress servers and the PHP backdoors that manage malicious injections.

### The Hypothesis

An adversary compromises a WordPress server using harvested credentials and installs a PHP backdoor or malicious plugin to facilitate the delivery of ErrTraffic ClickFix lures.

### How the hunt flows

The first phase narrows the investigation to relevant assets. The query identifies every host in the software inventory running WordPress. This step ensures that the subsequent, more resource-intensive queries only run against systems capable of hosting the targeted backdoor.

Next, the hunt gathers evidence from two distinct surfaces. It monitors web traffic for successful HTTP POST requests to the WordPress login page. It specifically flags status codes like 200 or 302 that indicate an account takeover. Simultaneously, the hunt scans file system activity in core directories like plugins, themes, and includes. It looks for the creation or modification of PHP files.

The hunt then baselines this file activity across the fleet. It filters for PHP files that appear on three or fewer hosts. Legitimate updates typically affect many servers at once, so these rare occurrences often represent manual attacker persistence or custom backdoor scripts.

Finally, a triage agent correlates these events. It links the successful login to the rare file modification on the same host. This connection provides a high-confidence indicator of a compromised administrator account being used to establish a foothold.

### What the hunt cannot see

This hunt has two primary blind spots. First, incomplete file telemetry on Linux hosting servers might miss script injections if the system samples high-volume windows or ignores specific WordPress subdirectories. Second, depth of HTTP logging matters. If a web proxy only records status codes and not response bodies, it may miss successful logins that the application handles with a 200 OK but an internal error message.

### How to run the hunt

This hunt is available as an open `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any runtime that supports the `hunt.md` standard. The playbook includes the SQL queries and the triage logic required to baseline your WordPress environment and identify ErrTraffic infrastructure.
