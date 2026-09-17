# Hunting OWAReaper Browser Persistence and Mailbox Permission Hijacking

Recent research by Proofpoint, titled "Cleaning Out Inboxes: TA488 Outlook half-click exploit" (https://www.proofpoint.com/us/blog/threat-insight/cleaning-out-inboxes-ta488-comes-outlook-another-half-click-exploit), highlights a sophisticated browser-based implant known as OWAReaper. This threat actor leverages a half-click exploit to deploy JavaScript that persists in the browser's localStorage and hijacks Outlook Web Access (OWA) sessions. This hunt is designed to find the specific runtime behaviors of this implant and the server-side permission changes it leaves behind.

The core hypothesis is that the adversary has deployed OWAReaper to hijack Exchange APIs, allowing them to harvest tokens and modify folder permissions for organizational-wide access. This bypasses traditional host isolation because the implant operates within the user's trusted browser session, interacting directly with OWA's internal handlers to grant 'Owner' permissions to the 'Default' user alias on targeted mailboxes.

The hunt flow begins with scoping. We use vulnerability telemetry to identify Exchange servers or endpoints exposed to CVE-2026-42897, the XSS vulnerability that facilitates the initial delivery. This step establishes the potential blast radius within the estate before moving into behavioral analysis.

Next, we examine HTTP telemetry for OWAReaper's specific runtime interactions. The hunt looks for requests to internal OWA handlers such as owa/sessiondata.ashx and EWS calls used for token harvesting and folder updates. Seeing a sequence of these internal calls from a single client IP is a high-fidelity indicator of implant orchestration.

Simultaneously, we monitor for authentication anomalies resulting from permission manipulation. The hunt baselines cross-mailbox access to identify accounts where the 'Default' user alias has been granted Owner-level permissions. This allows us to find instances where users are accessing mailboxes they do not typically interact with, which is a key indicator of the lateral access OWAReaper enables.

Finally, we perform a triage step to correlate the API leads with the authentication shifts. By linking the timing of suspicious HTTP requests to the appearance of new cross-mailbox sign-ins, we can distinguish legitimate shared-mailbox usage from the malicious hijacking of the 'Default' user alias.

There are two primary blind spots to consider. First, without full TLS decryption of traffic to OWA endpoints, we cannot see the actual payload content written to localStorage, meaning persistence setup must be inferred from URL patterns. Second, because the implant's DOM manipulation is entirely client-side, standard endpoint or network telemetry will not capture the creation of the invisible elements used for data harvesting.

This is categorized as a hunt rather than a simple detection because it requires baselining and correlation to be effective. A single rule flagging EWS calls might generate excessive noise in a large organization. This hunt correlates those calls with the resulting authentication impact to identify true malicious behavior. You can run this hunt by importing the hunt.md playbook into Huntbase or any hunt.md-aware runtime.
