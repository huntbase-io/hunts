# Hunting OysterLoader Payloads: Vidar and Rhysida Post-Infection Behaviors

Recent research by Sekoia, [OysterLoader unmasked: the multi-stage evasion loader](https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/), details a multi-stage infection chain used to deliver infostealers and ransomware. While the loader itself employs various evasion techniques, the final-stage payloads—typically Vidar for credential harvesting or Rhysida for ransomware—leave distinct behavioral signatures on the endpoint. This hunt is designed to catch these payloads after they have been unpacked and executed in memory.

### The Hypothesis
Our hypothesis is that an adversary has successfully used OysterLoader to gain a foothold and has proceeded to deploy Vidar or Rhysida. We expect to find evidence of this through unauthorized access to browser profile data, the creation of bulk encrypted files, or the use of local proxy ports for Command and Control (C2) traffic, particularly on hosts running IT management software that OysterLoader is known to impersonate.

### How the Hunt Flows
The hunt begins by scoping the environment for hosts running software that OysterLoader frequently uses as a lure. This includes common tools like PuTTY, WinSCP, and AnyDesk. By focusing on these hosts first, we narrow our search to the most likely beachheads for trojanized installers.

Once scoped, the hunt pivots into parallel behavioral analysis. For Vidar, we look for non-browser processes attempting to read sensitive files within Chrome or Edge user data directories. This is a high-fidelity indicator of credential theft that often bypasses simple signature-based detection of the stealer binary itself.

Simultaneously, we stack-count rare processes that lack valid digital signatures or company metadata. Because OysterLoader often executes payloads in memory or through hollowed processes, identifying these anomalies helps uncover the unpacked malware. We also monitor for the high-frequency file creation patterns associated with Rhysida ransomware, specifically looking for the `.rhysida` extension and ransom notes.

Finally, we examine network connections for multi-hop proxy behavior. Both Vidar and Rhysida frequently use Tor or local SOCKS proxies (on ports like 9050 or 1080) to mask their C2 traffic. We correlate these network events with the suspicious processes identified in previous steps to build a high-confidence case for infection.

### What This Hunt Cannot See
There are inherent limitations to this approach. We rely on endpoint telemetry; if an infection occurs on an unmanaged or BYOD device, we will have no visibility. Additionally, if the Rhysida configuration is modified to use a different file extension or if Vidar uses a custom browser profile path not covered in our queries, those specific activities may be missed. The hunt is also focused on post-exploitation; it does not aim to catch the initial OysterLoader delivery.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. You can import it directly into Huntbase or any runtime that supports the `hunt.md` format. It is designed to be run against your EDR or log aggregation platform using the provided SQL-based queries to identify and correlate behavioral indicators across your fleet.
