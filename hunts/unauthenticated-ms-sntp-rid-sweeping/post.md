# Detecting Unauthenticated MS-SNTP RID Sweeping and Timeroasting

### Why Now

Credential harvesting often relies on authenticated access, but Timeroasting provides a path for an adversary to collect password-derived data before they ever compromise an account. This hunt design builds on the research published by Huntress in [Detecting Timeroasting the Hard Way](https://www.huntress.com/blog/detecting-timeroasting). It addresses the difficulty of finding these attacks in noisy NTP traffic by correlating network volume with specific configuration changes and offensive tool artifacts.

### The Hypothesis

An adversary performs unauthenticated MS-SNTP RID sweeping against Domain Controllers to harvest password-derived MACs. This activity often follows a configuration downgrade on the target to allow legacy MD5 authenticators, making the harvested data easier to crack offline.

### How the Hunt Flows

The hunt first identifies the active Domain Controllers in the environment. It searches for hosts running the Kerberos Key Distribution Center (KDC) service. This scoping step ensures the analyst focuses subsequent high-volume network queries on the correct infrastructure.

Next, the hunt runs a parallel investigation into network activity and process execution. The network query identifies source IPs making hundreds of requests to Domain Controllers over UDP port 123. Simultaneously, a process query looks for known roasting tools like netexec, kerbwolf, or timeroast.py on endpoints. An analyst then weighs these signals; a single source IP generating a massive spike in NTP traffic while running offensive tooling suggests an active sweep.

Finally, the hunt checks the registry configuration of the targeted Domain Controllers. It specifically looks for the SignatureAuthAllowed value set to 0. This setting forces the use of weaker MD5-based authenticators. When a configuration downgrade aligns with a network sweep, it confirms a coordinated effort to harvest and crack credentials.

### What the Hunt Cannot See

This hunt relies on connection metadata and endpoint telemetry. It cannot inspect the actual MS-SNTP packet payloads. Without Deep Packet Inspection (DPI), an analyst cannot distinguish between legacy 68-byte authenticators and modern 120-byte extended authenticators. The hunt also faces a visibility gap regarding unmanaged devices. If an adversary performs a sweep from a BYOD laptop or an unmonitored segment, the activity is invisible unless network flow logs cover those client subnets.

### How to Run It

This hunt is provided as an open hunt.md playbook. You can import the markdown file directly into Huntbase or any runtime that supports the hunt.md standard. The playbook includes the necessary SQLite queries for service identification, volumetric network analysis, and registry state checks. Because NTP traffic is naturally periodic, we recommend running this as a periodic hunt to capture new spikes over a 14-day lookback window.
