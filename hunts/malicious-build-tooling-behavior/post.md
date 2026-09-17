# Hunting Malicious Build Tooling in Flutter and Dart Environments

The security landscape for developers is shifting as supply chain attacks move beyond simple package typosquatting into sophisticated environment weaponization. A recent report by OSSPREY (https://www.ossprey.com/blog/pub-dev-compromise) details a compromise in the pub.dev ecosystem where malicious Dart and Flutter packages are used to inject persistence and exfiltration mechanisms directly into a developer's build process. We have designed a new hunt to detect the specific behaviors and artifacts associated with this campaign.

### The Hypothesis
Our hunt is based on the hypothesis that an adversary has compromised a local development or CI/CD environment by injecting malicious hooks into project configuration files. Specifically, the adversary uses malicious packages to modify Gradle or Xcode build scripts, resulting in the execution of obfuscated shell commands during the project compilation phase. These hooks are designed to be stealthy, often hiding within standard build steps to maintain long-term access to the developer's credentials and signing keys.

### How the Hunt Flows
The hunt begins with a scoping phase focused on software inventory. Rather than scanning the entire fleet, we narrow our focus to hosts that have the Flutter or Dart SDKs installed. This ensures that our high-intensity file and script queries are only executed on machines that actually perform the targeted build activities, reducing noise and performance impact on unrelated systems.

Once the scope is defined, the hunt pivots to script activity analysis. We look for a very specific pattern of obfuscation highlighted in the OSSPREY report: the use of `printf` and `tr` to reconstruct commands like `xxd` or `base64`. This technique is frequently used by the injector to bypass string-based script scanners that look for common encoding or decoding utilities. Finding this pattern on a developer machine is a high-fidelity indicator of malicious build-time activity.

Simultaneously, we examine the file system for artifacts left behind by automated script edits. The injector often uses tools like `sed` to modify `build.gradle` files in place, which frequently creates `.gradle.bak` backup files. In a standard development workflow, these backup files are rare. Finding them sibling to a build configuration file suggest an automated, and potentially unauthorized, modification has occurred.

Finally, the hunt inspects the Xcode environment for misplaced trigger files. The reported campaign uses a clever trick where a `README.md` file is placed inside the `ios/` or `macos/` subdirectories and used as an input for a malicious `PBXBuildRule`. By baselining the presence of README files across the fleet, we can identify these anomalous placements that serve as the trigger for malicious code execution during Xcode builds.

### Blind Spots and Limitations
This hunt relies heavily on the visibility of script content and file-system activity. If the EDR solution does not capture the full command-line arguments of shell executions or if it lacks visibility into the specific marker `A3EA261` inside `.pbxproj` files, the hunt may only identify that a file was modified without confirming the malicious nature of the modification. Furthermore, if an attacker moves away from standard `printf` and `tr` patterns, the script-based detection will require updates to match new obfuscation styles.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It is designed to be imported into Huntbase or any other `hunt.md`-aware runtime. Because it includes automated triage steps, it can quickly provide a per-host verdict of 'malicious' or 'suspicious' by correlating software presence, script behavior, and file-system artifacts, allowing analysts to focus only on the most likely compromises.
