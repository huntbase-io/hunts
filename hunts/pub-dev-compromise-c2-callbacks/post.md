# Hunting C2 Callbacks from Malicious pub.dev Flutter Packages

### Why now

A recent report from OSSPREY ([pub.dev compromise: malicious Dart/Flutter packages](https://www.ossprey.com/blog/pub-dev-compromise)) details how attackers uploaded malicious versions of `universal_file_viewer` and `surveyjs_flutter` to the pub.dev registry. These packages injected code into Gradle and Xcode build scripts. Once executed during a build, this code initiates a second-stage download via an HTTP POST request to a rotating set of .ru domains. Because developer machines and CI/CD pipelines often have broad network access, these callbacks can easily go unnoticed in standard traffic logs.

### The Hypothesis

We hypothesize that developer workstations or CI runners have executed malicious build hooks, resulting in beaconing to rotating .ru domains via POST requests to the `/a` path. We expect to see these network signals originating specifically from processes associated with build tooling, such as Java, Xcode, or the Flutter SDK.

### How the hunt flows

The hunt begins by scoping the environment using the `hb_software_inventory` surface. We look specifically for the compromised versions of the packages identified in the report: `universal_file_viewer` (v0.1.5, v0.1.6) and `surveyjs_flutter` (v0.1.1, v0.1.2, v0.1.3). Identifying these hosts provides the high-confidence starting point for deeper investigation.

Next, the hunt moves into a parallel discovery phase. We utilize `hb_dns_activity` to perform fleet-wide stacking of .ru domain queries. By focusing on domains seen on three or fewer hosts, we can isolate the rotating C2 infrastructure from common Russian web services. Simultaneously, we inspect `hb_http_activity` for the specific behavioral signature: an HTTP POST request to the `/a` path.

To capture instances where HTTP metadata might be missing, we also examine `hb_network_connection`. We look for outbound connections to .ru TLDs or suspicious IP ranges that originate from known build tools like `java`, `xcodebuild`, `dart`, or `flutter`. This ensures we catch the callback even if the process name or protocol varies slightly from the initial report.

Finally, a triage step correlates the findings. A host that both contains a malicious package version and exhibits rare .ru network activity is prioritized for immediate isolation and credential rotation.

### What this hunt cannot see

There are two primary blind spots to consider. First, network log retention is a factor. If the compromise occurred early in the reported window (mid-August) and your logs only go back 14 days, the initial callback activity will be invisible. Second, if the C2 communication is performed over HTTPS and your environment lacks TLS inspection, the specific `/a` path will not be visible in `hb_http_activity`. In such cases, the hunt relies entirely on DNS rarity and process-to-IP correlations.

### How to run it

This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any runtime that supports the open hunt.md specification. The playbook includes the specific SQL queries for software inventory, DNS stacking, and network metadata analysis, allowing you to run the entire sequence against your telemetry provider with minimal manual adjustment.
