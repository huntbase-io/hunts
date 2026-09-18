# Aeternum Malware Endpoint Execution and Startup Persistence Hunt

The emergence of Aeternum represents a shift toward more resilient command-and-control (C2) architectures. As detailed in the Unit 42 report, [The Permanent Threat: Analyzing Aeternum’s Blockchain-Based C2 Operations and Communications](https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/), this malware family leverages the Polygon blockchain to retrieve C2 instructions. While network-based detection of these JSON-RPC requests is possible, the decentralized nature of the infrastructure makes endpoint-based hunting a more stable approach for identifying compromised hosts.

Our hypothesis for this hunt is that regardless of how the instructions are received, the Aeternum loader must establish persistence and execute from predictable user-writable paths. We expect to find Aeternum loader binaries that persist via Windows Startup shortcuts and execute from subdirectories within the user profile to drop secondary payloads such as miners or RATs. This hunt is designed to catch the malware where it is most vulnerable: its residency on the host.

### How the Hunt Flows

The hunt begins with a scoping phase focused on software inventory. The Unit 42 research identified PuTTY version 0.83 as a specific marker used during Aeternum's testing and deployment phases. We use this as a high-fidelity pivot to identify candidate hosts that may have been part of a campaign. By narrowing our initial scope to these systems, we can reduce the volume of data processed in subsequent high-intensity behavioral steps.

Once candidate hosts are identified, the hunt pivots to file system activity. We look for the creation of rare .lnk files within the Windows Startup directory. Aeternum typically uses specific naming conventions for these shortcuts to ensure the loader restarts upon user login. By calculating the prevalence of these shortcuts across the environment, we can isolate those that appear on only a handful of systems, which is a strong indicator of targeted or malicious persistence rather than standard enterprise software behavior.

Simultaneously, the hunt examines process execution telemetry. We specifically look for binaries running from the `AppData\Local` directory, focusing on those with names associated with the Aeternum framework or those that match known UPX-packed loader patterns. This step identifies the active execution phase of the malware, confirming that the persistent shortcuts are successfully launching the intended payload.

Finally, the hunt correlates these findings with the arrival of secondary impact payloads. We search for the execution of well-known malicious binaries like XMRig or XWorm that are often deployed as the final stage of an Aeternum infection. By linking the initial loader behavior to these impact processes, the hunt provides a complete picture of the infection chain on a per-host basis.

### What This Hunt Cannot See

This hunt relies heavily on host-based telemetry. Its primary blind spot is the lack of coverage on unmanaged or non-enrolled assets; if a device is not running a monitoring agent, its file and process activity will not be captured. Additionally, because the loader may be short-lived—terminating immediately after establishing persistence or spawning a child—standard snapshot-based inventory might miss the initial execution of the primary 'Build.exe' binary if it occurs between collection intervals.

### How to Run This Hunt

This hunt is packaged as an open `hunt.md` playbook. It can be imported directly into Huntbase or any other runtime environment that supports the `hunt.md` format. Because it correlates data across software inventory, file activity, and process execution surfaces, it is best run as an integrated sequence. The results will provide a list of hosts showing the full infection chain, allowing for rapid triage and containment of the Aeternum threat.
