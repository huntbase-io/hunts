# Hunting for AMOS and Windows Loader Post-Exploitation Artifacts

### Why Now

Recent reporting by Huntress in their article [Post-DEF CON Phishing Uses Malicious Google Doc to Deliver Malware](https://www.huntress.com/blog/defcon-phishing-google-doc-malware) highlights a campaign targeting security practitioners with highly specific document lures. These lures were designed to deliver the AMOS (Atomic macOS Stealer) to Mac users and various loaders to Windows users. While the initial access vector is well-documented, the post-exploitation artifacts—such as credential staging and persistence mechanisms—provide a reliable surface for retrospective hunting in environments where the initial delivery might have bypassed email gateways.

### The Hypothesis

We hypothesize that an intruder successfully bypassed initial defenses and has since staged stolen credentials in local temporary directories or established persistence via macOS LaunchDaemons and Windows UpdateCache directories. Specifically, we expect to see evidence of data collection in non-standard staging paths and persistence entries that point back to the known command-and-control (C2) infrastructure reported in the campaign.

### How the Hunt Flows

The hunt begins with a scoping phase across the `hb_file_activity` surface. We look for the creation or modification of specific filesystem markers, such as the `/tmp/lksopo` directory on macOS or unusual activity within the Windows `UpdateCache` and `Temp` directories. This initial sweep narrows the investigation to hosts where the malware has moved beyond execution to the staging or persistence phase.

Next, the hunt pivots to investigate persistence specifically on macOS. We query for the `com.xdivcmp.plist` LaunchDaemon. Rather than just looking for the filename, the hunt examines the command lines associated with scheduled jobs to identify any that point to the reported C2 domains, such as `apple-googleapi.com`. This ensures that even if the attacker renames the persistence file, the functional behavior remains visible.

For Windows endpoints, the hunt focuses on identifying rare binaries. By stack-counting executables dropped into staging directories like `UpdateCache` or `Downloads`, we can isolate anomalies. The malware in this campaign often uses legitimate-sounding names like `DockerDesktopSvc.exe` to blend in; however, these files are statistically rare in the directories where they are staged compared to the rest of the fleet.

Finally, we correlate these endpoint anomalies with network telemetry. We look for direct IP connections and HTTP traffic to known malicious infrastructure, including `86.54.25.213` and associated `.lat` domains. This correlation is critical to distinguishing an active compromise with exfiltration from an unsuccessful execution of the payload.

### Blind Spots

This hunt has two primary blind spots. First, macOS TCC (Transparency, Consent, and Control) visibility limits our ability to see which specific files within the `Notes.app` or other protected locations were accessed, even if we see the final staging in `/tmp`. Second, if the malware uses short-lived heartbeats or UDP-based communication that falls outside the granularity of network connection logging, the network correlation phase may produce false negatives.

### How to Run It

This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any hunt.md-aware runtime that supports SQL-based telemetry analysis. The playbook is structured to be run as an iterative process, starting with broad scoping and narrowing down to specific host triage through parallel evidence gathering.
