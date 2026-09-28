# Monitoring ErrTraffic Infrastructure on Compromised WordPress Servers

### Why track ErrTraffic now
Recent research from Sekoia, titled "ErrTraffic: A Growing ClickFix Malware Distribution Framework" (https://www.sekoia.com/blog/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework), details an evolving Malware-as-a-Service system. The adversary compromises WordPress servers to host the ErrTraffic framework, which currently resolves C2 via blockchain RPCs and serves ClickFix lures from specific JavaScript endpoints. This hunt targets the server-side presence of this framework to identify compromised assets in your environment.

### The Hypothesis
An intruder compromises WordPress servers to host the ErrTraffic framework. This framework relies on EtherHiding, a technique where C2 domains are retrieved from blockchain smart contracts, allowing for rapid infrastructure rotation. The infected servers serve malicious scripts through specific paths to unsuspecting visitors.

### How the Hunt Flows
The hunt begins by identifying every host likely running a WordPress installation. A scoping query checks for active processes like php-fpm, httpd, or nginx that interact with WordPress-specific directories. This step ensures we monitor both managed servers and unmanaged or containerized installations that might exist outside standard inventory.

Once the scope is set, the hunt runs three parallel checks to gather independent evidence of compromise. First, it monitors HTTP traffic for requests hitting known ErrTraffic lure delivery endpoints like /cf.js and /api/css.js. These are high-fidelity indicators that a server is actively participating in a ClickFix campaign.

Second, the hunt looks for unauthorized persistence. It identifies new or modified PHP files within the WordPress plugin and theme directories. The adversary often plants backdoors in these locations to maintain control over the distribution node. An analyst looks for XOR-obfuscated strings or unusual actor accounts creating these files.

Third, the hunt examines DNS resolution patterns for C2 activity. It flags connections to public blockchain RPC providers, such as Polygon or QuickNode, which the framework uses to fetch its next C2 domain. It also monitors for lookups to suspicious TLDs like .beer, .cfd, and .sbs that are commonly used in the ErrTraffic infrastructure.

### What the Hunt Cannot See
This hunt has two primary blind spots. First, if an attacker modifies existing core WordPress files with minimal code changes rather than adding new files, simple file creation auditing may miss the change. Second, if the RPC traffic to blockchain providers is fully encrypted and the smart contract logic changes, identifying the secondary C2 via DNS alone becomes more difficult. High-fidelity verification still requires inspecting the identified PHP files for malicious logic.

### How to Run This Hunt
This hunt is provided as an open hunt.md playbook. You can import this file directly into Huntbase or any hunt.md-aware runtime to execute the queries across your fleet. Because this hunt correlates activity across four different telemetry surfaces — processes, file changes, HTTP traffic, and DNS — it identifies infections that individual static detections often miss.
