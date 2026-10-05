# Hunting UAT-11587 Antino Backdoor and Microsoft 365 C2

### Why this hunt

An analyst looking at recent China-nexus activity will find the report from Cisco Talos titled China-nexus UAT-11587 targets government and policy organizations across Asia with Antino backdoor (https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/). The adversary uses a sophisticated multi-stage infection process to deploy a Rust-based backdoor. This threat is notable because it uses legitimate Microsoft 365 services for command and control (C2), blending malicious traffic with standard business operations. We developed this hunt to help practitioners detect this specific chain from initial staging to cloud-based exfiltration.

### The Hypothesis

The adversary stages infection payloads on Cloudflare Pages and CloudFront to deliver the Antino backdoor via script loaders. Once executed, the backdoor establishes persistence using registry Run keys and initiates communication with Microsoft 365. The adversary uses OneDrive and Exchange as a dead-drop C2 channel to bypass traditional network security controls and blend into legitimate cloud traffic.

### How the hunt flows

The hunt begins with a scoping phase that examines DNS telemetry. The first query identifies hosts resolving known delivery domains such as osc-cdn.com. This narrows the investigation to systems that interacted with the adversary's staging infrastructure within the specified lookback period.

After identifying suspect hosts, the hunt pivots to process and script telemetry to find the loader. We search for script engines like mshta.exe or wscript.exe launched by common user applications like Outlook or web browsers. Simultaneously, the hunt examines script activity logs for the same Cloudflare and CloudFront URL patterns to confirm the loader logic actually ran on the endpoint.

The next phase focuses on the backdoor's persistence. The hunt scans registry activity for new Run keys pointing to binaries in user-writable paths like AppData or Users\Public. By filtering for low-prevalence entries seen on only a few hosts, an analyst can isolate the specific persistence mechanism used by the Antino backdoor across the estate.

Finally, the hunt triages Microsoft 365 cloud API logs. It looks for anomalous file uploads or message creation in OneDrive and Exchange that suggest dead-drop C2 behavior. The hunt correlates these cloud events with the previously identified host-based indicators to provide a complete picture of the infection from the initial phishing click to active data exfiltration.

### What the hunt cannot see

This hunt has two primary blind spots. First, Microsoft 365 Unified Audit Logs often experience ingestion delays of up to 24 hours. This means immediate C2 activity may be invisible during the initial run of the hunt. Second, if the adversary uses advanced obfuscation within the HTA or WSF script blocks, the specific commands executed by the stagers may remain hidden unless the environment supports full script block logging and de-obfuscation.

### How to run it

We provide this hunt as an open hunt.md playbook. You can import this file into Huntbase or any hunt.md-aware runtime to execute the queries across your telemetry surfaces. The playbook is structured to guide an analyst through the scoping, evidence gathering, and final verdict phases without requiring manual correlation of host and cloud events.
