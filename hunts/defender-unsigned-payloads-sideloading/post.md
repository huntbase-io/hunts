# Hunting Unsigned Payloads and DLL Side-Loading Tagged by Defender

### Why This Hunt Matters

Most commodity intrusions pass through the same step: a file arrives in a user's profile from a browser, an archive or a messaging app, and runs. The file is often an unsigned executable, or a malicious DLL placed beside a signed program that will load it. Defender frequently does not detect the payload, but it does make a note of it.

[Protokol-7 documented](https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html) the path tags Defender writes into its encrypted database, `mpenginedb.db`. `NewPECreatedNoCert` marks an unsigned PE being created, `ExecutedPENoCert` marks one being run, `BM_IsPotentialSideLoad` marks likely side-loading, and `NewlyCreatedZip` marks a new archive. Their examples included an unsigned PE in a temp folder and `ffmpeg.dll` and `pcaui.dll` in unusual places. Defender also queues executables it saw dropped and then run. The tags last about two weeks. The open-source [osquery-defender-extension](https://github.com/rakeshrm/osquery-defender-extension) exposes them as osquery tables.

### The Hypothesis

A loader was written into a user-writable folder and run: either an unsigned executable, or a DLL beside a signed program. Defender tagged the file and raised no detection.

### How the Hunt Flows

Microsoft does not document these tags, so the hunt first counts every tag the fleet produces, per host. A tag that appears on only one or two hosts, or one not yet in the hunt's list, is worth reading in full.

The main query then lists every tagged file in a user-writable folder with all of its tags, its current SHA-256 and its Authenticode result. A file tagged both created and executed without a certificate was dropped and run. The hunt stacks hashes across the fleet: an installer that unpacks under `AppData` on hundreds of machines falls away, and a binary seen on one host remains.

Two queries show how the files arrived. One is Defender's own dropped-and-executed queue. The other is file-write telemetry, which counts the rare executables written to user space and names the process that wrote them. A browser, 7-Zip, Explorer extracting a zip, Teams, Slack, Telegram or Discord writing a rare binary is how most loaders land. An agent combines the evidence and names the suspect files.

For the suspect hosts, the hunt checks for side-loading directly. It looks for a process loading a DLL that is not validly signed from the same user-writable folder as its own image. It also looks at what the payload started. A second agent gives a verdict per file. Malicious files go to an approval-gated action that preserves the file and the `Scans` folder, then isolates the host and scans the folder.

### What the Hunt Cannot See

Tags expire after about two weeks, so older drops are gone unless the query is scheduled. Tag meanings are inferred from their names and Protokol-7's observations. When a tagged file has been deleted, there is nothing left to hash or verify. Defender's hash cache still holds its hash, but only with an MFT reference, not a path. Payloads signed with stolen or abused certificates never get the NoCert tags. Side-load confirmation needs image-load telemetry, which many fleets do not collect.

### How to Run It

The hunt is a `hunt.md` playbook for Huntbase or any runtime that reads the format. The Defender steps are osquery queries that need the `defender_mpengine` extension loaded on Windows hosts; in Huntbase they run through Endpoint Control. Start with workstations. Once benign hashes are on an allow list, the main query makes a good daily scheduled query.

Credit for the research behind the extension goes to Protokol-7, whose write-up and tooling decoded `mpenginedb.db`.
