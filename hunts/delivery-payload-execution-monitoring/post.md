# Hunting Initial Access through Delivery and Execution Monitoring

### Why this hunt?
Adversaries often bypass perimeter security by exploiting the human element or the software supply chain. The Unit 42 report, Top 5 Initial Access Threat Vectors Observed by Unit 42 in September 2026 (https://unit42.paloaltonetworks.com/top-5-initial-access-vectors-september-2026/), highlights that phishing and supply chain lures remain primary entry points. We designed this hunt to identify the footholds these vectors create on the endpoint.

### The Hypothesis
An adversary establishes initial access through a compromised supply chain or a phishing attachment, resulting in unusual package installations or rare process execution from browser-originating downloads.

### How the Hunt Flows
The hunt begins with a scoping phase that inspects the hb_application_lifecycle surface. The first query identifies unusual or unsigned software installations, focusing on packages that lack valid signer subjects or originate from external HTTP URIs. This step narrows the investigation to hosts where potentially malicious software recently entered the environment.

After identifying candidate hosts, the hunt pivots to two parallel evidence-gathering streams. One stream queries hb_process_activity for rare processes running from user-writable paths like Downloads, Temp, or Public folders. By calculating the prevalence of these paths across the fleet, the hunt filters out common installers and highlights unique binaries that may represent a payload execution.

The second parallel stream monitors hb_file_activity to corroborate the delivery method. It searches for browser or mail processes writing files with executable or container extensions, such as .exe, .msi, or .iso. This provides the context needed to determine if a rare process launch originated from a recent download.

The final phase uses an automated agent to weigh the evidence from all three surfaces. The agent evaluates the installation history, the rare process launches, and the browser activity per host to produce a final verdict. This automated triage connects the delivery and execution events, reducing the time an analyst spends manually linking logs.

### What the Hunt Cannot See
This hunt relies on specific endpoint telemetry. If a host lacks an active agent, it provides no signals and remains an invisible foothold. Furthermore, the application lifecycle surface primarily captures MSI and AppX installations; the hunt may miss legacy standalone executable installers that do not register through these providers.

### Running the Hunt
This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. Because the logic relies on prevalence and cross-surface correlation, it identifies anomalies that signature-based tools often miss.
