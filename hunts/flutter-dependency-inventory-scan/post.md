# Scanning for Malicious Dart and Flutter Packages in Developer Environments

Recent research from Ossprey titled [pub.dev compromise: malicious Dart/Flutter packages](https://www.ossprey.com/blog/pub-dev-compromise) highlighted a sophisticated supply chain attack targeting Flutter developers. Malicious packages like `universal_file_viewer` and `surveyjs_flutter` were found to use hex-encoded Gradle and Xcode scripts to exfiltrate environment variables and SSH keys during the build process. Because these packages often mimic legitimate libraries, standard detection rules may miss them if they are not updated frequently with specific indicators.

### The Hypothesis
We hypothesize that an intruder has introduced malicious Dart or Flutter packages into the environment. These packages are detectable as rare or recently added dependencies within local developer toolchains or internal package mirrors that mimic popular libraries but exhibit anomalies in visibility and creation timing.

### How the Hunt Flows
The hunt begins by scoping the environment for hosts that have Dart or Flutter related software. This narrows the focus to developer workstations and CI/CD runners where these packages are most likely to reside. We then baseline the prevalence of all identified packages, focusing specifically on those appearing on fewer than five hosts. This surfaces the 'long tail' of dependencies where targeted malicious packages often hide.

Once potential candidates are identified, the hunt pivots into a parallel corroboration phase. We collect detailed inventory paths and version strings from the endpoints while simultaneously querying internal GitHub package repositories. We are looking for private internal mirrors that share names with public packages but were created during the known window of the pub.dev compromise. This helps identify internal propagation where a developer might have inadvertently mirrored a malicious package for the rest of the team.

Finally, the triage phase uses an automated agent to compare the gathered inventory against known-malicious versions (such as 0.1.1 through 0.1.6) and flags suspicious creation dates. If a match is found, the playbook provides instructions for host isolation and secret revocation.

### Blind Spots
There are two primary areas this hunt may miss. First, malicious packages may reside in hidden user-level directories, such as `~/.pub-cache`, which may not be fully captured by standard OS-level software inventory scans. Second, if a malicious package is pulled in as a transitive dependency through a complex internal library, it might only appear in a `pubspec.lock` file rather than the top-level inventory, requiring recursive lockfile parsing for full visibility.

### Why This is a Hunt
This is structured as a hunt because it relies on prevalence baselining and cross-surface correlation rather than static signatures. By comparing internal GitHub metadata against endpoint inventory, we find anomalies that a standard EDR or software composition analysis (SCA) tool might overlook. 

### How to Run It
This playbook is provided as a `hunt.md` file. It can be imported into Huntbase or any other `hunt.md`-aware runtime. It requires access to endpoint software inventory data and GitHub package metadata.
