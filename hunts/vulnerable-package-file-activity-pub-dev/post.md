# Hunting Malicious pub.dev Packages and Flutter Build File Tampering

Recent research from Ossprey (https://www.ossprey.com/blog/pub-dev-compromise) identified a supply chain attack targeting Flutter developers. Specifically, the packages `universal_file_viewer` and `surveyjs_flutter` were found to contain malicious post-install logic. This hunt is designed to find evidence of these packages and, more importantly, the artifacts they leave behind when tampering with native build environments.

### The Hypothesis
Our hypothesis is that an adversary has compromised developer workstations or CI/CD runners by distributing these infected packages. Once installed, the packages modify native build configuration files—like Gradle and Xcode project files—to achieve persistence and execute code during the build process.

### How the Hunt Flows
The first phase involves a broad scoping query against the software inventory surface (`hb_software_inventory`). We look specifically for the affected versions of the malicious packages (0.1.1 through 0.1.6). Because these packages might be cleared from a local cache after an injection, we treat this as a scoping step rather than a definitive answer.

In the second phase, we pivot to file-system activity (`hb_file_activity`). We search for a specific behavioral marker: the creation of zero-byte `README.md` files within `ios/` or `macos/` subdirectories. The attacker uses these files to trigger custom Xcode build rules. This is a high-fidelity indicator because standard Flutter development rarely involves placing README files in these specific platform paths.

We also examine modifications to native build scripts like `build.gradle.kts` and `project.pbxproj`. By filtering out standard development tools—such as Flutter, Dart, and Xcode itself—we can identify anomalous processes that are attempting to inject code into the build pipeline. This helps isolate the 'injector' process responsible for the tampering.

Finally, we perform a prevalence analysis on `pubspec.lock` modifications. Because lockfiles are updated frequently, we look for rare processes that touch these files across the fleet. A standard developer workflow will show fleet-wide consistency; a custom injection script will appear as an outlier on a small number of hosts.

### Blind Spots
This hunt relies on the visibility of file activity within developer home directories and project folders. If EDR logging is restricted to system paths, the injection will be invisible. Furthermore, while we can see that a file was modified, we cannot see the specific content (such as the `A3EA261` string mentioned in the source) without forensic collection or script block logging. Manual inspection of flagged build files is required to confirm the presence of obfuscated payloads like `xxd` or `printf` hooks.

### Running the Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime that supports the `hunt.md` format. It is designed to be run periodically against developer-heavy organizational units to ensure no malicious packages have entered the supply chain.
