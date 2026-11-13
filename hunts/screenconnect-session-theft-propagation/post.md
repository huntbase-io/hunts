# ScreenConnect Session Hijacking and SCKit Worm Propagation

### Why Now
A recent report by Huntress, "SCKit Worm Installs Rogue ScreenConnect Clients and Session Cookie Relays" (https://www.huntress.com/blog/sckit-worm-rogue-screenconnect), details a worm targeting managed service providers to spread malicious clients. This threat propagates by compromising technician workstations and hijacking RMM sessions to push rogue clients to downstream endpoints. The worm represents a significant shift in how attackers target MSPs by using a technician's own tools and trust against the entire customer estate.

### Hypothesis
The adversary harvests technician session cookies from local browser profiles using SQLite scripts to move laterally through the ScreenConnect Shared Toolbox.

### How the Hunt Flows
The hunt begins by identifying the execution of core SCKit scripts, such as Panel-Lateral.ps1 and LabConfig.ps1, alongside the specialized ToolboxRelayUploader.exe binary. It specifically scans for sqlite3.exe instances interacting with browser Cookie or Login Data files. This is a high-confidence signal because technicians rarely have a legitimate reason to programmatically query their own browser data folders.

Once potential beachheads are identified, the hunt pivots to verify the rarity of the uploader binary across the environment using stack-counting. It simultaneously checks for DNS lookups to known relay infrastructure, such as relaytrap.cs and ns.mo7sen.dev, from those same endpoints. These domains coordinate the uploader’s activity and facilitate the theft of technician session data.

Finally, a triage agent evaluates the evidence. If script execution correlates with C2 network activity and the presence of rare uploader binaries, the agent marks the host as malicious. The hunt includes an automated isolation step to take these hosts offline, preventing the worm from using the technician's hijacked session to push payloads to the wider network via the ScreenConnect Shared Toolbox.

### Blind Spots
This hunt requires full process command-line visibility to distinguish legitimate SQLite usage from cookie theft. If the EDR truncates logs, identifying the target path becomes difficult. Additionally, the hunt cannot see C2 traffic if the adversary employs DNS-over-HTTPS (DoH) to resolve relay domains, as these lookups will not appear in standard DNS telemetry.

### How to Run
This hunt is an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md standard. Use the lookback_days parameter to adjust the search window, and provide known technician hostnames as a filter to reduce noise from developers who may legitimately use SQLite utilities.
