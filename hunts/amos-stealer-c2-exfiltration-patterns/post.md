# Hunting AMOS Stealer Through Network Exfiltration and Stage Patterns

### why now

An August report from Unit 42 — Atomic macOS (AMOS) Stealer Activity (https://unit42.paloaltonetworks.com/atomic-macos-amos-stealer-activity/) details how AMOS stealer targets high-value data like AWS credentials and cryptocurrency wallets. The malware uses a series of network-based exfiltration steps to transmit stolen assets to its operators.

### the hypothesis

The adversary exfiltrates sensitive browser and wallet data by sending a sequence of HTTP POST requests containing specific stage parameters. These parameters, such as "stage=init_session" and "stage=credentials", indicate which category of stolen data the malware is transmitting to its command-and-control infrastructure.

### how the hunt flows

The first phase checks network telemetry for direct connections to known malicious IP addresses. This provides a quick way to identify hosts communicating with infrastructure reported in recent AMOS campaigns.

The second phase runs two concurrent searches. The first query looks for behavioral patterns in HTTP POST requests across the fleet, specifically searching for the characteristic stage parameters used by the malware. The second query checks DNS activity for resolutions of domains associated with the delivery and operation of the stealer.

In the third phase, an agent triages the findings from the network, HTTP, and DNS surfaces. It weighs the presence of specific exfiltration stages against the reputation of the destination infrastructure to settle a verdict for each affected host.

The final phase handles the response logic. If the agent confirms a malicious infection, the playbook routes the host for isolation to prevent further data loss. An analyst then conducts a forensic review to identify on-disk persistence artifacts in locations such as the Application Support directory.

### why this is a hunt

Standard detection rules often fail because the adversary rotates command-and-control infrastructure daily. This hunt goes beyond simple indicator matching by focusing on the durable behavioral logic of the malware's exfiltration process. By identifying the sequence of data transmission stages, we can find malicious activity even when the specific network nodes are new or undocumented.

### what the hunt cannot see

The hunt relies on visibility into HTTP request details. If the malware uses encrypted channels without TLS inspection, query parameters like the stage values remain hidden. In those cases, the hunt must rely on less specific IP and DNS metadata. Additionally, if the adversary changes the names of the stage parameters, the behavioral queries will require updates to maintain their effectiveness.

### how to run it

This hunt is an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md standard. The parameters allow you to adjust the lookback window and update the lists of known IP addresses and domains as new intelligence becomes available.
