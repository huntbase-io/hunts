# Hunting Unauthorized RMM and Ransomware Precursors

### Why Now
Cisco Talos recently highlighted the complexity of modern intrusions in [The Fine Art of Frustrating the Adversary](https://blog.talosintelligence.com/the-fine-art-of-frustrating-the-adversary/). They detail how attackers use legitimate tools to blend into environment noise. This hunt focuses on one of the most common dual-use patterns: Remote Monitoring and Management (RMM) software. While these tools facilitate IT administration, they also provide adversaries with persistent access and a platform for lateral movement.

### The Hypothesis
An adversary uses unauthorized remote management tools to maintain persistence and performs credential harvesting or stages ransomware encryption.

### How the Hunt Flows
The first phase scopes the environment by identifying hosts running common RMM software. The query checks for process names like AnyDesk, ScreenConnect, and Atera. Because many organizations use at least one of these tools for legitimate support, this step is a filter rather than a definitive alert. It builds a list of candidate hosts for deeper inspection.

Once the hunt identifies hosts with RMM activity, it initiates a parallel check for high-risk behaviors. One branch examines process telemetry for signs of credential harvesting. It specifically looks for command-line arguments targeting LSASS memory, such as minidump calls via `comsvcs.dll` or the use of ProcDump and Mimikatz. These actions frequently follow the establishment of an RMM-based foothold.

Simultaneously, the hunt monitors file system telemetry for mass modification events. The playbook looks for a high volume of unique file updates or renames on the same hosts. This behavioral indicator suggests the encryption phase of a ransomware attack is underway. Identifying this volume-based anomaly allows an analyst to catch the impact phase before the entire disk is lost.

In the final phase, the analyst correlates the findings. If a host running an unauthorized tool also exhibits LSASS dumping or mass file modification, the playbook provides instructions for immediate network isolation. If the tool presence is the only indicator, the workflow shifts to a manual verification task with IT asset owners to confirm if the software is a known exception.

### Blind Spots
Visibility relies entirely on endpoint agent coverage. The hunt cannot see unauthorized tools running on unmanaged or shadow IT devices that lack the necessary telemetry. Furthermore, sophisticated adversaries might bypass command-line detection by using direct API calls or custom binaries to access memory. This hunt prioritizes high-confidence process and file indicators but may miss entirely in-memory techniques.

### How to Run It
This hunt is a standard `hunt.md` playbook. It imports directly into Huntbase or any runtime that supports the `hunt.md` specification. The queries target `hb_process_activity` and `hb_file_activity` surfaces. Analysts should adjust the `rmm_names` parameter to exclude tools officially supported by their local IT department to reduce initial scoping noise.
