# Hunting Tampered Exodus Wallet Installers and Modular RATs

Recent research from Huntress, titled [The Crypto Wallet That Never Opened: Tampered Exodus Installer Hides a Modular RAT](https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat), details a campaign where a modular Remote Access Trojan (RAT) is delivered via a tampered MSI. The installer mimics a legitimate Exodus wallet but includes several anomalies in its metadata and deployment behavior. Most notably, the malware attempts to hide its command-and-control (C2) traffic by communicating with legitimate Exodus infrastructure, making simple domain-reputation filters ineffective.

### The Hypothesis
Our hypothesis is that we can identify these compromised systems by looking for the specific, fictional metadata used in the tampered installer—such as a fake 'Apple Inc' manufacturer label—and then pivoting to process execution and network telemetry. We expect the malicious binary to run from a non-standard directory in the user profile and exhibit anomalous DNS request patterns to legitimate domains to mask its actual C2 activity.

### How the Hunt Flows
The hunt begins with a scoping phase focused on software inventory. We look for a package named 'Background Service' or an entry with a manufacturer of 'Apple Inc' at version 43.4.30. These are the specific markers identified in the research for the tampered MSI. While legitimate software might share some characteristics, this specific combination is a strong indicator of the presence of the malicious installer.

Once potential hosts are identified, the hunt pivots to process activity. We look for any execution of 'exodus.exe' originating from the `%APPDATA%\ExdBackupTool\` directory. This is a critical pivot because legitimate Exodus installations do not typically reside in this specific subfolder. Finding a process here provides high confidence that the binary is the modular RAT rather than the actual wallet application.

To corroborate the findings, the hunt examines network telemetry in two parallel tracks. First, it searches for DNS queries to legitimate Exodus domains. Because the RAT uses these to mask its traffic, a high volume of these queries coming from the suspicious process path is an indicator of C2 masking. Second, the hunt looks for direct connections to the hard-coded IP infrastructure used during the delivery or fallback phases of the infection.

Finally, the hunt includes an agent-based triage step to synthesize these findings. If a host shows both the suspicious process path and the anomalous network activity, the hunt provides instructions for isolation and forensic collection of the artifacts in the AppData directory.

### Blind Spots and Limitations
There are two primary blind spots to consider. First, if the malware uses its own DNS-over-HTTPS (DoH) resolver, standard endpoint DNS logs will not capture the masking queries. Second, the network signals rely on lookback windows; if the initial infection and C2 activity occurred outside the retention period, the hunt must rely solely on the inventory and process markers.

### Running the Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime capable of parsing the `hunt.md` format. The parameters for lookback and known malicious IPs are configurable, allowing you to adjust the scope based on your environment's telemetry retention.
