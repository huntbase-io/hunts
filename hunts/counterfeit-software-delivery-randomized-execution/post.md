# Hunt for counterfeit installers and randomized malware execution

### Why now

Microsoft recently detailed a campaign in their article, "Counterfeit installers to system compromise: Tracking a deceptive software download campaign." The report describes an adversary, tracked as Silver Fox or Yinhu, who uses search engine optimization and spoofed vendor sites to deliver polymorphic malware. These attackers impersonate common software like Razer, Kaspersky, and Microsoft Edge to gain initial access. Because the payloads use server-side regeneration to vary their hashes, static signatures often fail.

### The hypothesis

An intruder establishes initial access by tricking a user into downloading a polymorphic installer from a spoofed vendor site. This installer then launches a masqueraded payload from a randomized directory, such as ProgramData or a user's Public folder, to evade standard application controls.

### How the hunt flows

The hunt begins by establishing context through software inventory. An analyst first identifies hosts running the specific software packages the campaign is known to impersonate. While this step does not confirm an infection, it highlights systems where a user might be more susceptible to a look-alike update lure.

The first active lead uses DNS activity to find resolutions of known spoofed domains. This query targets infrastructure mimicking legitimate vendor sites. Because behavioral audits of process execution are resource-intensive, the hunt uses a gate. It only proceeds to deep behavioral queries if the DNS lead confirms a host contacted a malicious domain.

When the gate opens, the hunt runs two behavioral audits in parallel. The first audit examines process activity to detect binaries launched by archiver tools like WinRAR or 7-Zip from randomized subfolders in Public or ProgramData. It uses stack-counting to isolate rare binaries that appear on only a few hosts, filtering out legitimate enterprise-wide software.

The second behavioral audit inspects file metadata. The adversary often fabricates resource strings to masquerade as legitimate products. This query specifically looks for processes carrying the company name "Speech Processing Solutions GmbH" or original filenames like "PhilipsSpeechDriverConfiguration.exe" when they appear in unexpected paths. A triage agent finally correlates the DNS hits, software lures, and rare process executions to provide a final verdict.

### What the hunt cannot see

This hunt has two primary blind spots. First, if a browser uses DNS-over-HTTPS (DoH) to resolve the spoofed domains, the DNS lead query will return zero results. In this scenario, the gate stays closed, and the hunt misses the subsequent execution. Second, the metadata audit relies on specific fabricated strings identified in the source research. If the actor rotates the brands they impersonate, the metadata query will not flag the new samples.

### How to run it

This hunt is available as an open hunt.md playbook. You can import the playbook into Huntbase or any runtime that supports the hunt.md format. The playbook includes the logic to scope the search, gate the expensive behavioral queries, and route confirmed findings to isolation.
