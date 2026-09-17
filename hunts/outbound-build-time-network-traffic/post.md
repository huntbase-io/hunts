# Hunting Outbound Network Traffic from Malicious Flutter Build Tools

Recent research by OSSPrey titled "pub.dev compromise: malicious Dart/Flutter packages" (https://www.ossprey.com/blog/pub-dev-compromise) highlights how attackers can inject malicious network-fetching logic directly into build-time components such as Gradle and Xcode. When a developer runs a build, these scripts can exfiltrate sensitive environment variables or SSH keys to attacker-controlled infrastructure. This hunt design focuses on detecting that specific exfiltration behavior.

### The Hypothesis
Our hypothesis is that an adversary who has successfully compromised a developer's package dependency will establish C2 communication during the build process. This manifests as rare outbound connections—DNS lookups, HTTP POSTs, or raw socket connections—originating from build tools like `dart`, `java/gradle`, or `xcodebuild` rather than the developer's browser or typical communication apps.

### How the Hunt Flows
The hunt begins by scoping the environment to active developer machines. We use the `hb_file_activity` surface to identify hosts where build configuration files, such as `pubspec.lock`, `build.gradle`, or `project.pbxproj`, are frequently modified. This allows us to focus our network analysis on systems currently performing build operations, reducing the data volume from the rest of the fleet.

Once the scope is narrowed, we concurrently examine three network-related surfaces. For DNS activity, we look for low-prevalence external domains queried by build processes, filtering out common internal or known-good infrastructure. For HTTP activity, we specifically target rare POST requests from these workstations, as these are often used for exfiltration. Finally, we look at raw network connections to identify outbound traffic to non-standard ports or rare destination IPs that deviate from the baseline of a typical development cycle.

In the final phase, an automated triage step correlates the identified active build environments with the rare network events. The goal is to surface hosts that exhibit both behaviors simultaneously, which is a high-fidelity indicator of a potential supply chain compromise.

### What the Hunt Cannot See
There are two primary blind spots to consider. First, without full HTTP request body inspection, we can identify that a POST request occurred to a suspicious endpoint, but we cannot confirm the exact content of the payload (e.g., whether it contained specific tokens). Second, in cloud-based CI/CD environments where process-to-network mapping is not available through endpoint agents, we may lose the context of which specific build tool initiated a connection, relying instead on VPC-level flow logs.

### Why This Is a Hunt
A standard detection rule might alert on any connection to a suspicious TLD, but in a developer environment, this often leads to high false-positive rates due to the variety of mirrors and repositories used. This hunt layers file-system behavior with process-specific network telemetry. By requiring the intersection of "active build activity" and "rare process-specific outbound traffic," we identify behavior that static indicators might miss.

### How to Run It
This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any other `hunt.md`-aware runtime for execution. The playbook is designed to be run periodically against your developer population to identify compromised dependencies that have successfully bypassed code-level reviews.
