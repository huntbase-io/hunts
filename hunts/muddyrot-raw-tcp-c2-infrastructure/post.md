# MuddyRot Implant Command and Control via Raw TCP Sockets

### The Shift from RMM to Custom Tooling

Recent reporting by Sekoia in their article [MuddyWater replaces Atera with custom MuddyRot implant](https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/) highlights a tactical evolution by the MuddyWater (MOIS) threat group. While they previously relied on legitimate remote management tools like Atera, they have transitioned to a custom C2 implant called MuddyRot. This transition is significant because it moves the adversary's footprint from 'living-off-the-land' software to a bespoke binary that uses an obfuscated raw TCP protocol for its heartbeat and command execution.

### Hypothesis

We hypothesize that MuddyRot can be identified by looking for command-and-control activity that utilizes raw TCP sockets on port 443. Because this traffic is not HTTP-compliant, it will leave a distinct gap in telemetry where network connection logs exist, but corresponding HTTP/TLS proxy or application-layer logs are absent. Furthermore, we expect the implant to reside in specific, non-standard directories in `ProgramData` used for masquerading.

### How the Hunt Flows

The hunt begins with a scoping phase using the `hb_network_connection` surface. We look for direct connections to known C2 IP addresses identified in the research. This provides immediate visibility into any hosts currently beaconing to known-bad infrastructure on port 443. 

Next, we pivot to process behavior on the endpoint using `hb_process_activity`. We specifically search for the execution of `documentsmanagerreporter.exe` or any binaries originating from the `\programdata\softwarememory\` directory. This directory is not a standard location for legitimate software, making activity here a high-confidence indicator of the MuddyRot implant.

We then look for behavioral anomalies by baselining port 443 traffic. Using the `hb_network_connection` surface, we identify rare external destinations that have only been contacted by a small handful of hosts. This helps identify new or rotating C2 infrastructure that may not yet be in threat intelligence feeds.

Finally, we perform a protocol validation check. By joining our list of suspicious 443 sockets against `hb_http_activity`, we look for the absence of records. If a host is maintaining a persistent socket on port 443 but generates zero HTTP request logs for that destination, it suggests the use of a custom protocol like MuddyRot’s raw TCP implementation.

### What This Hunt Cannot See

There are two primary blind spots in this design. First, the hunt relies on endpoint-side network socket telemetry. If an affected host does not have an active agent or if network flow logging is unavailable for that segment, the beaconing will be invisible. Second, while the absence of HTTP logs is a strong indicator, it is an inference. Without deep packet inspection (DPI) or raw PCAP analysis, we cannot definitively prove the obfuscated heartbeat is present solely through metadata.

### Why This is a Hunt, Not a Detection

While a single rule can flag a known IP, this is structured as a hunt because it requires a multi-dimensional pivot. We are not just looking for a single indicator, but rather a correlation between process path, destination rarity, and the negative signal of missing protocol logs. This approach minimizes false positives from legitimate raw TCP applications and allows us to find previously unknown infrastructure.

### How to Run It

This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any other `hunt.md`-aware runtime. The queries are written in a generic SQL dialect (SQLite) designed to be translated to your specific data lake or EDR provider.
