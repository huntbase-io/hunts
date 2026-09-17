# Hunting TA488 OWAReaper Network C2 and Exfiltration Patterns

Our team has published a new hunt.md playbook designed to uncover the network-based command and control (C2) and exfiltration channels used by TA488’s OWAReaper implant. This research follows the technical analysis by Proofpoint, [Cleaning Out Inboxes: TA488 Comes for Outlook with Another Half-Click Exploit](https://www.proofpoint.com/us/blog/threat-insight/cleaning-out-inboxes-ta488-comes-outlook-another-half-click-exploit), which details how this actor leverages Outlook Web Access (OWA) to maintain a stealthy, browser-resident presence.

### The Hypothesis
We hypothesize that an adversary has deployed OWAReaper to maintain persistence within the browser environment. To avoid detection, the implant fetches victim-specific commands via GitHub commit searches and exfiltrates session data through public image CDN proxies (like weserv.nl or WordPress). This activity blends into legitimate web traffic but leaves specific footprints in HTTP and DNS telemetry.

### How the Hunt Flows
The hunt begins with a scoping phase to identify Exchange servers or endpoints currently vulnerable to CVE-2026-42897. This vulnerability is the primary entry point for OWAReaper. If vulnerability data is unavailable, the hunt pivots to examining all hosts interacting with OWA services.

Next, the hunt executes three parallel inquiries into network telemetry. The first looks for specific queries to the GitHub Commit Search API. OWAReaper uses these to retrieve commands embedded in commit metadata, a technique that allows the actor to avoid hosting dedicated C2 infrastructure. We look for these requests originating from non-developer workstations.

Simultaneously, the hunt analyzes HTTP traffic for outbound connections to common image CDNs. We look for URI patterns associated with OWAReaper’s asset management and exfiltration, such as paths containing "msanalytics.json" or "sessiondata.ashx". These services are often used as relays to move data to the actor-controlled domain, acocdn.com.

The final technical phase examines DNS activity. We baseline the acocdn.com domain to identify hosts generating high volumes of unique subdomains. This is a common indicator of DNS tunneling being used as a fallback C2 or exfiltration relay when HTTP channels are restricted.

### What the Hunt Cannot See
There are two primary blind spots in this design. First, because the hunt relies on URI path analysis, it cannot verify the content of the data being exfiltrated without Deep Packet Inspection (DPI) or full body capture. We are identifying suspicious paths, not the actual bytes moved. Second, the implant's primary persistence mechanism—residing in the browser's localStorage—is invisible to standard file and registry monitoring. This hunt focuses on the network "exhaust" because the host-side mechanics are intentionally ephemeral.

### Why This Is a Hunt, Not a Detection
A standing detection rule for traffic to GitHub or image CDNs would be impossibly noisy for most organizations. This is a hunt because it requires correlating multiple low-confidence signals—GitHub API calls, specific CDN URI strings, and DNS query volume—to form a high-confidence verdict on OWAReaper activity. It is designed to find the subtle anomalies that occur after a compromise has already bypassed traditional endpoint security.

### How to Run It
This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any runtime that supports the open hunt.md specification. Once imported, you can configure the lookback period and the specific CDN domains relevant to your environment.
