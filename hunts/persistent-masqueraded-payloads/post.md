# Hunting persistent payloads masquerading as legitimate software installers

Adversaries frequently abuse user trust by packaging malware within installers for legitimate utilities. A recent report by the Microsoft Security Response Center (MSRC), [Counterfeit installers to system compromise](https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/), details how the Silver Fox campaign uses deceptive downloads to gain a foothold. This hunt focuses on the persistence phase of that campaign, where the adversary deploys payloads with stolen metadata into randomized directories.

### The Hypothesis
We hypothesize that an adversary is using world-writable directories (like `C:\Users\Public` or `C:\ProgramData`) to host binaries that claim to be legitimate software from vendors like Philips Speech Processing or Indigo Rose. By using randomized subdirectories and filenames, they bypass simple path-based blocklists. We expect to find these binaries coupled with scheduled tasks to maintain persistence across reboots.

### How the Hunt Flows
The hunt begins by examining process activity for binaries that contain specific metadata strings—such as "Philips Speech Driver" or "Indigo Rose"—but are executing from suspicious locations. This initial filter targets the defense evasion technique of masquerading, where the internal metadata of the PE file does not match the expected installation path of legitimate software.

Next, the hunt pivots to correlate these processes with persistence mechanisms and forensic artifacts. We look for scheduled tasks that point to the same world-writable directories, as Silver Fox often uses tasks to re-execute their loaders. Simultaneously, we search for temporary file artifacts created by the Indigo Rose TrueUpdate runtime, which provides high-fidelity evidence of the specific installer framework used in this campaign.

Finally, we apply a fleet-wide rarity filter. Legitimate installations of specialized software typically appear across a consistent set of paths or on many hosts within a specific department. In contrast, the randomized paths used by this adversary are likely to be unique to a single host. By identifying binaries in Public or ProgramData that are seen on three or fewer machines, we can isolate the most suspicious leads for analyst review.

### Blind Spots and Limitations
This hunt relies heavily on the availability of PE metadata (Company Name and Description) in your endpoint telemetry. If your environment only logs process names and paths without version information, the first phase will fail to distinguish between randomized malware and legitimate temporary files. Additionally, if the adversary deletes the binary immediately after execution, a hunt focused on file paths may result in dead ends. We recommend ensuring that file deletion events are captured to correlate against the scheduled task commands.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime that supports the `hunt.md` format. Because this is a hunt rather than a static detection, it is designed to be run periodically to baseline your environment and identify anomalies that have already bypassed your existing perimeter and endpoint controls.
