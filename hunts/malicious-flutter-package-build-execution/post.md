# Hunting for Malicious Flutter Package Build-Time Execution

The recent OSSPREY report, "pub.dev compromise: malicious Dart/Flutter packages" (https://www.ossprey.com/blog/pub-dev-compromise), detailed a supply chain attack where legitimate Flutter packages were backdoored with build-time RCE. Our team has drafted a hunt.md playbook to help practitioners identify if these packages have entered their environment and whether they have successfully executed.

### Hypothesis
We hypothesize that an attacker has compromised a Flutter package maintainer to inject build-time RCE. This results in developer or CI machines downloading malicious dependencies that execute arbitrary code—often to exfiltrate secrets—and beacon to C2 infrastructure during the build process.

### The Hunt Flow
The hunt begins by auditing software inventory. We look specifically for the known malicious versions of universal_file_viewer and surveyjs_flutter. This scoping step focuses the investigation on hosts that are theoretically at risk due to the presence of these packages in their managed software lists.

Next, we pivot to file activity logs. We look for modifications to sensitive build configuration files, such as build.gradle and project.pbxproj. The focus here is on identifying rare processes—anything other than standard Git or IDE tools—that are writing to these files. This helps identify the injection mechanism used by the malicious packages.

The third phase is a parallel check across network and repository signals. We monitor for DNS and network connections to known C2 domains like elvynforge.xyz, but specifically where the source process is a build tool like gradle, xcodebuild, or flutter. Simultaneously, we check internal GitHub mirrors to see if the malicious packages have been cached within the organization.

Finally, the results are triaged to find the intersection: hosts that have the malicious package, have seen unauthorized build file changes, and show network activity originating from build processes.

### Blind Spots
The primary blind spot is the local user cache. Many Flutter developers have dependencies in ~/.pub-cache/, which may not appear in standard system-level software inventory scans. If a malicious version is sitting in a cache but has not been used in a build yet, this hunt may miss it. Additionally, if network logging lacks process attribution, it becomes difficult to distinguish malicious build activity from unrelated web traffic.

### How to Run
This is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to automate the data collection and triage. The logic is defined in portable SQL, allowing you to adapt the queries to your specific EDR or log aggregation platform if needed.
