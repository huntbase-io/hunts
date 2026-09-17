# Hunting for Malicious Build Execution in Flutter and Dart Projects

The Ossprey team recently published a detailed analysis of a [pub.dev compromise](https://www.ossprey.com/blog/pub-dev-compromise) involving malicious Dart and Flutter packages. These packages, such as `universal_file_viewer`, don't just sit idle; they weaponize the build process itself to achieve Remote Code Execution (RCE). By the time a developer realizes a package is suspicious, their build environment—and any credentials stored within it—may already be compromised.

### The Hypothesis
Our hypothesis is that an adversary is executing malicious code during the build phase of a Flutter or Dart project by using obfuscated shell commands (specifically the `printf | tr | sh` pattern) or malicious Xcode build rules. These methods are designed to bypass static source analysis and hide the secondary stage of the attack, which often involves downloading a payload or exfiltrating environment variables.

### How the Hunt Flows
The hunt begins with scoping. We use the `hb_software_inventory` surface to identify hosts that are either known Flutter/Dart development environments or have specific malicious packages installed. This narrows our focus to the high-risk estate: developer workstations and CI/CD runners.

Once scoped, we pivot to process execution patterns. We look specifically for the characteristic `printf | tr | sh` obfuscation pattern in `hb_process_activity`. This pattern was identified in the Gradle build hooks of the reported malicious packages and is used to decode and execute hidden scripts. This is a high-fidelity marker because while build tools execute many shells, they rarely use this specific piping sequence to obfuscate the command line.

In parallel, we examine the file system for artifacts associated with malicious Xcode PBXBuildRules. The reported exploit creates temporary `.out` files in `/tmp` using the `${INPUT_FILE_BASE}.out` naming convention. By searching `hb_file_activity` for these specific patterns created by Xcode or shell processes, we can identify iOS-specific build compromises.

Finally, we baseline the normal child processes of Java (Gradle) and Xcode. Legitimate builds are repetitive. We look for rare shell executions or network tool invocations (like `curl` or `wget`) that appear on only a few hosts. These outliers often represent the moment a build script deviates from the standard pipeline to reach out to a C2 server.

### What This Hunt Cannot See
This hunt has two primary blind spots. First, if the endpoint telemetry does not capture full command-line arguments for short-lived shell processes, the primary `printf` marker for the Gradle hook will be missed. Second, malicious build rules may delete their temporary artifacts in `/tmp` immediately after execution. If the file monitoring is based on periodic snapshots rather than real-time events, these traces may disappear before they are recorded.

### Why This Is a Hunt, Not a Detection
While the `printf | tr` pattern is highly suspicious, a simple detection rule might generate noise in complex, legitimate build environments that use unusual scripting for automation. This hunt is designed to correlate that behavior with the presence of specific packages and rare parent-child process relationships, providing the context necessary to distinguish a compromise from a creative build engineer.

### How to Run It
This hunt is provided as an open `hunt.md` playbook. It can be imported into Huntbase or any other `hunt.md`-aware runtime. The playbook includes the necessary queries for scoping, process analysis, and artifact discovery, allowing you to run the logic against your own telemetry providers.
