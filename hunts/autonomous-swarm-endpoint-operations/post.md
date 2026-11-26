# Hunting for Autonomous Swarm Endpoint Operations

### The Shift to Autonomous Swarms

%Recent research by Talos in "Oh, is it Thanksgiving? I hadn’t noticed" (https://blog.talosintelligence.com/oh-is-it-thanksgiving-i-hadnt-noticed/) highlights a shift toward autonomous agentic swarms. These systems coordinate over public infrastructure but leave distinct mechanical signatures on the host. We designed this hunt to identify these agents not just by what they are, but by how they behave. Autonomous swarms operate at machine speed, requiring a detection approach that focuses on temporal patterns rather than static signatures alone.

### The Hypothesis

An autonomous agentic swarm executes on endpoints, characterized by high-speed sub-second process bursts and predictable state-tracking file names like artex-probe. The automated nature of these systems creates an execution tempo that differs significantly from human-driven activity. While individual actions might appear benign, the frequency and coordination of these actions reveal the underlying agent logic.

### How the Hunt Flows

The first phase checks for known indicators of compromise. The query scans process activity for specific hashes and filenames, such as vid001.exe or content.js, identified in the Talos research. This step provides a fast lead if the swarm uses static, known components or scripts. It establishes the initial scope of potentially compromised hosts within the environment.

The hunt then pivots into two parallel behavioral searches. The first search examines file activity on the hb_file_activity surface. It identifies files created with predictable naming conventions like artex-probe-%. Swarms use these files as local beacons to coordinate state across multiple distributed agents. Finding these files suggests that an agentic framework is actively managing tasks on the endpoint.

The second parallel search analyzes process launch timing on the hb_process_activity surface. It identifies bursts where more than five processes launch within a single second on one host. This timing is a hallmark of automated agent reasoning, where a controller spawns multiple sub-processes to perform discovery or execute commands in rapid succession. This behavioral marker helps find agents even after they rotate their file hashes or modify their binary names.

In the final phase, an automated agent triages the results from both the IOC lead and the behavioral searches. It weighs the presence of known indicators against the evidence of high-speed bursts and coordination files. If the activity shows coordinated agent behavior, the playbook routes the host for isolation. This step prevents further coordination and allows for forensic capture of the in-memory swarm state.

### What the Hunt Cannot See

This hunt faces two primary blind spots. First, if a swarm executes its logic faster than the EDR telemetry collector captures events, the sub-second bursts might appear fragmented or disappear entirely. The current query relies on one-second buckets, which might miss staggered or extremely rapid execution. Second, agents may delete their state-tracking probe files within milliseconds of creation. If the telemetry does not record the file creation event in real-time, these indicators remain hidden.

### How to Run This Hunt

The team provides this hunt as an open hunt.md playbook. An analyst imports it into Huntbase or any runtime that supports the hunt.md format. The playbook allows for scoping the search to specific high-risk servers or development environments where swarm-driven operations, such as container escapes, are most likely. Running the hunt periodically helps identify machine-speed threats that evade standard threshold-based detections.
