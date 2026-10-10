# Hunting for MATCHBOIL Downloader Persistence and Activity

### Why Now

ESET Research recently detailed a campaign by the UAC-0099 group using a C# downloader known as MATCHBOIL (see [MATCHBOIL: New tricks, same old evil intentions](https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/)). The adversary targets Ukrainian governmental and energy organizations by deploying loaders that fingerprint victim systems and maintain persistence using user-profile directories. This hunt focuses on identifying the specific lifecycle of this downloader across the endpoint and network.

### The Hypothesis

An adversary deploys a MATCHBOIL downloader that establishes persistence through Registry Run keys or scheduled tasks after performing WMI-based system discovery to uniquely identify the victim host. The malware relies on script-based loaders to arrive on the system and uses hardware-specific serial numbers to ensure its C2 communication is unique to each victim.

### How the Hunt Flows

The hunt begins with a scoping phase on the `hb_file_activity` surface. The adversary typically creates a directory named DeviceMonitor within the Local AppData folder and drops a config.ini file to manage state. We search for these specific folder patterns and filenames to find hosts that have already transitioned to the payload delivery stage.

Once we identify suspicious hosts, we pivot to initial execution leads. The hunt examines the `hb_script_activity` and `hb_process_activity` surfaces in parallel. We look for VBScript or PowerShell loaders that use XMLHTTP objects to fetch payloads, alongside wmic.exe commands querying CPU and BIOS serial numbers. Finding a script-based arrival coupled with hardware reconnaissance provides a high-confidence lead for an active MATCHBOIL infection.

In the validation phase, we look for established persistence and C2 metadata. We query `hb_registry_activity` for Run keys pointing to the DeviceMonitor path and `hb_scheduled_job` for tasks named CheckTask. We then correlate these endpoint triggers with `hb_http_activity`. Recent variants use a hardcoded 25-character User-Agent string. By baselining User-Agent lengths and filtering for rare values that meet this length, we isolate the C2 channel from legitimate background traffic.

This is a hunt rather than a simple detection because Registry Run keys and scheduled tasks in user directories are frequently used by benign software updaters. A standalone detection rule would produce high volumes of noise. This hunt requires the correlation of file creation, WMI-based discovery, and specific HTTP metadata to confirm the full attack lifecycle before an analyst acts.

### Blind Spots

This hunt has two primary blind spots. First, MATCHBOIL can perform WMI reconnaissance directly through .NET APIs like ManagementObjectSearcher. If the malware calls these APIs internally rather than spawning wmic.exe, the discovery phase will be invisible to process-line monitoring. Second, the use of HTTPS for C2 communication prevents the inspection of the hex-encoded payload within the network traffic. Analysts must rely on User-Agent length and endpoint file artifacts to confirm the infection.

### How to Run This Hunt

This hunt is provided as an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md specification. Once imported, the playbook guides you through the scoping queries, the parallel execution of discovery checks, and the final correlation of persistence mechanisms to produce a host-based verdict.
