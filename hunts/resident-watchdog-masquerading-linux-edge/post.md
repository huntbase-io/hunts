# Hunting Resident Implants on Linux Edge Appliances

### Why this hunt?
Edge appliances are high-value targets for persistent, silent access. Research from Rapid7, "SMTP is the key: BPFDoor and AVERAT hitting the network edge" (https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge), details how attackers use regionalized process masquerading to blend into these environments. Standard file-based detections often miss these implants because the dropper deletes its secondary binaries shortly after execution.

### The Hypothesis
An intruder has installed persistence on a Linux appliance by using a shell script to stage binaries in /sbin, then deleting the files to leave the processes running as fileless masqueraded daemons.

### How the hunt flows
The first phase identifies the fleet's Linux appliances by looking for activity in non-standard mount paths like /addpkg/ or /hdd/. It then searches for evidence of the initial infection or the shell-script staging mechanism, specifically looking for files like updiptable.php or dropper hashes identified in the research.

The second phase pivots to behavioral markers of residency. We stack-count processes across the fleet to find rare instances of binaries running without an on-disk image. The hunt looks for processes adopting common daemon names like ntpdate, udevds, or chronyd that appear on very few hosts.

The final phase identifies environment variable manipulation used to suppress forensic evidence. The hunt searches for command lines containing HISTFILE=/dev/null or HISTSIZE=0, which attackers use to hide their activity from system logs.

### Blind Spots
If the staging script exists for less than the polling interval of the telemetry sensor, the creation and deletion event may be missed. Additionally, BPFDoor uses a passive backdoor trigger that does not bind to a port, making it invisible to conventional socket monitoring. This hunt relies on process masquerading markers to bridge that gap.

### How to run it
This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your environment.
