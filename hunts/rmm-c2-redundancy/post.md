# Hunting Rogue ScreenConnect and UltraViewer Persistence

### Why this hunt
Huntress recently published "Rogue ScreenConnect Installations Across Unrelated Hosts" (https://www.huntress.com/blog/rogue-screenconnect-installations). The report describes how adversaries deploy legitimate remote management tools for persistence. These tools, such as ScreenConnect and UltraViewer, often bypass detection because they are signed and common. When an adversary deploys them, they leave traces on the network and the filesystem. This hunt identifies those traces.

### Hypothesis
An adversary stages rogue ScreenConnect instances and secondary RMM tools to maintain persistence. They use non-standard ports and run rare binaries from user-writable directories.

### How the hunt flows
We begin the hunt by examining the network plane. The first query searches hb_network_connection for traffic to known command-and-control IP addresses or port 8041. Port 8041 is a specific indicator for the rogue ScreenConnect activity mentioned in the source. This step identifies hosts with suspicious communication patterns.

Once we identify leads, the hunt gathers corroborating evidence in two parallel steps. We check hb_dns_activity for resolutions of dynamic DNS domains linked to the attacker's infrastructure. This confirms if a host reaches out to known relay points. Simultaneously, we search hb_process_activity for ScreenConnect or UltraViewer processes. We specifically look for these binaries running from user-controlled paths like AppData or the Temp directory.

The hunt then performs a prevalence analysis. We stack-count unique process paths and file names across the entire organization. We focus on instances appearing on three or fewer hosts. This separates legitimate RMM software from isolated installations. An analyst reviews these outliers to determine if the software is unauthorized.

The final phase applies an automated triage process. An agent evaluates the network, DNS, and process data to assign a verdict. If a host shows both suspicious network connections and rare process execution, the hunt recommends isolation. An analyst then checks the process tree for the VBS loader chain associated with this activity.

### What the hunt cannot see
The hunt has two blind spots. If the attacker uses DNS-over-HTTPS (DoH), the DNS lookup queries remain hidden from standard logs. We also cannot see the specific URL path for staged downloads from services like Dropbox without full HTTP decryption. The adversary also avoids detection if they use existing, authorized RMM tools for their activity.

### How to run it
This playbook is a hunt.md file. Analysts import this file into Huntbase or any hunt.md-aware runtime. The playbook automates the collection and triage steps. It runs the lead queries and process-stacking logic against the environment to find rogue RMM patterns.
