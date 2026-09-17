# Hunting AMOS and NetSupport Data Staging and C2 Polling

Recent research from Huntress, [Post-DEF CON Phishing Uses Malicious Google Doc to Deliver Malware](https://www.huntress.com/blog/defcon-phishing-google-doc-malware), highlights a campaign using deceptive Google Docs to deliver AMOS (Atomic macOS Stealer) and NetSupport. While delivery vectors change, the operational patterns of these stealers often remain consistent during the collection and exfiltration phases.

### The Hypothesis

We hypothesize that an intruder is actively staging stolen credentials, browser data, and cryptocurrency wallet information in temporary directories—such as `/tmp/lksopo` on macOS or specific `UpdateCache` paths on Windows—before exfiltrating this data via HTTP polling to hard-coded C2 infrastructure.

### The Hunt Flow

This hunt begins with scoping through the `hb_software_inventory` surface. Rather than searching the entire fleet, we prioritize hosts running high-value targets for stealers, such as messaging applications like Telegram or cryptocurrency wallets like MetaMask and Ledger. This narrow focus allows for more intensive analysis of the following phases without generating excessive noise.

Next, the hunt pivots to `hb_file_activity` to detect the presence of malicious staging and configuration files. We look specifically for the creation and modification of files in the temporary directories used by these loaders. Finding these staging artifacts is a high-confidence indicator of an active or recent infection where data has likely been aggregated for theft.

To confirm exfiltration, we analyze `hb_network_connection` and `hb_http_activity`. This phase correlates the hosts found in the previous step with rare IP connections and specific HTTP request patterns. We look for polling signatures, such as requests to `/log` or `/api/v1/bot/actions/`, and connections to known campaign IPs. This dual-layered approach helps identify C2 traffic even if the adversary has rotated domain names.

Finally, a triage step weighs the convergence of file staging and network traffic. A host showing both the specific staging folders and the unique HTTP polling behavior is a high-confidence candidate for immediate isolation and incident response.

### Blind Spots and Limitations

This hunt has two primary blind spots. First, if the environment does not have TLS inspection at the perimeter or endpoint-based HTTP visibility, the specific URI paths used for polling may be invisible. In such cases, the hunt relies on IP-level metadata, which is more prone to infrastructure rotation. 

Second, the staging files are often ephemeral. If the malware deletes its staging directory immediately after a successful exfiltration and the telemetry is not captured in real-time, the file-based leads may be missed. The hunt assumes a lookback period that overlaps with the collection event.

### How to Run the Hunt

This design is published as a `hunt.md` playbook. It is a portable, structured format that can be imported directly into Huntbase or any hunt.md-aware runtime. By providing the specific surfaces and logic needed to bridge macOS and Windows telemetry, it allows practitioners to search for these campaign artifacts across a diverse fleet without manual query translation.
