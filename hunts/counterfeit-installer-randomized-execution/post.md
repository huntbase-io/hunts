# Hunting for Silver Fox Counterfeit Installers and Randomized Payloads

The Silver Fox (Yinhu) campaign continues to evolve, using sophisticated server-side regeneration to deliver unique payloads to each target. Microsoft's recent report, [Counterfeit installers to system compromise: Tracking a deceptive software download campaign](https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/), highlights how actors impersonate popular software vendors to lure users into downloading malicious archives. Because the payloads are frequently regenerated, static indicators like file hashes are ineffective for detection at scale.

### The Hypothesis
Our hypothesis is that an intruder has directed users to spoofed vendor domains (impersonating brands like Razer, Kaspersky, or Calibre) to download archive-wrapped installers. These installers execute randomized stage-one payloads from user-writable paths, specifically `C:\Users\Public` or `C:\ProgramData`, which are then identifiable by their low prevalence across the fleet.

### How the Hunt Flows
The hunt begins with a scoping step that identifies hosts running the legitimate versions of the software being impersonated. By filtering for users who already use Razer or Kaspersky products, we narrow our focus to the most likely targets of an 'update' or 'installer' lure. This prevents the hunt from being overwhelmed by noise in the subsequent network phases.

Next, the hunt pivots to DNS activity. We look for resolutions to a known list of lure and delivery domains within the scoped group of hosts. Any resolution to these domains is considered a high-confidence indicator of interest or a direct redirect to campaign infrastructure, providing a temporal anchor for the investigation.

Following the network signals, the hunt executes a parallel check for execution patterns. We look for specific installer naming conventions (e.g., `a_instapp`, `ainstaller-`) and simultaneously baseline the execution of rare binaries in `C:\Users\Public` and `C:\ProgramData`. By filtering for binaries that appear on only one or two hosts across the entire environment, we can isolate the randomized stage-one payloads characteristic of this campaign.

Finally, the hunt uses an agent triage step to correlate these signals. It links the initial domain visit to the subsequent execution of a suspicious binary on the same host. This contextual correlation is what allows us to confirm a compromise where a standalone detection might only alert on a suspicious (but possibly legitimate) installer name.

### What the Hunt Cannot See
There are two primary blind spots in this design. First, the hunt relies on endpoint agent presence for process and file visibility. If a user on an unmanaged asset resolves a lure domain, we will see the network activity but cannot confirm if a payload executed. Second, without SSL/TLS interception, we can see the DNS request for the delivery host but cannot identify the specific ZIP archive retrieved, making it difficult to confirm the download without host-side forensics.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any runtime that supports the open hunt.md standard. It is designed to be run periodically—ideally every 14 days—to catch new infrastructure as it is spun up by the actor.
