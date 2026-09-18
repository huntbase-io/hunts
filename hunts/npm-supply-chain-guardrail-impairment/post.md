# Detecting Removal of npm Package Cooldown Security Settings

Supply chain attacks often move faster than traditional detection. When a package is compromised and published, there is a narrow window before it is yanked where it can do the most damage. To combat this, newer versions of npm (11.10+) introduced a `min-release-age` configuration—a cooldown period that prevents the installation of very recently published packages. However, as noted by Elastic Security Labs in their article "The security signal log tailing can't see: tracking npm cooldown removals with Elastic Agent", simply having the feature is not enough if users or attackers can silently disable it.

We have published a new hunt focused on identifying the impairment of these npm guardrails.

### The Hypothesis
The hunt operates on the premise that an intruder or an insider has removed the `min-release-age` security setting from an npm configuration (`.npmrc`). The goal of this impairment is to allow the installation of a recently published malicious package that would otherwise be blocked by the cooldown timer.

### How the Hunt Flows
The hunt begins by scoping the fleet to identify where npm is actually present. By querying software inventory, we focus the subsequent, more intensive queries on developer workstations and build servers where `.npmrc` files are likely to exist. This prevents wasting resources on the entire fleet.

Next, we look for rare modifications to `.npmrc` files. Because these files change infrequently in a stable environment, we use stack-counting to isolate outliers. This step does not look for specific content changes yet, but rather identifies hosts where the configuration file was modified or deleted in a way that deviates from the norm.

Once a set of suspicious hosts is identified, the hunt pivots into parallel evidence gathering. We look for explicit command-line activity where `npm config delete min-release-age` was executed. Simultaneously, we look for `npm install` commands and DNS queries to the npm registry occurring on the same host within the same timeframe. This correlation is what distinguishes a routine config change from a security bypass intended to facilitate a package download.

Finally, the triage stage correlates these signals. We are not just looking for a file change; we are looking for a file change followed immediately by a network-heavy installation process.

### Blind Spots
This hunt has two primary limitations. First, standard file activity logs tell us a file was modified, but not how. If a user changes the cooldown timer from 2 days to 0 seconds rather than deleting the setting entirely, this hunt will see it as a generic modification. Full visibility into this would require file content snapshots or specific configuration auditing.

Second, the hunt focuses on the top-level installation. If a malicious package is pulled in as a transitive dependency (a dependency of a dependency), the `npm install` command might look benign. Detecting this requires analyzing the `package-lock.json` or SBOM data, which is outside the scope of this endpoint-centric hunt.

### How to Run This Hunt
This hunt is packaged as an open `hunt.md` playbook. It is designed to be portable and can be imported into Huntbase or any other `hunt.md`-aware runtime. It uses a series of structured SQL-like queries across file, process, and network surfaces to provide a comprehensive view of the bypass attempt.
