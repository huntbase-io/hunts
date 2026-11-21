# Hunting for Rebranded SoftEther VPN Bridges

### Why Now

Rapid7 recently published [Spying on Governments with Zero Lines of Malware: A Custom SoftEther Bridge in Webworm’s Toolkit](https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge). The research details how the Webworm APT uses an altered version of the SoftEther VPN bridge, dubbed NtMonitor, to establish persistent ingress and egress. Instead of developing custom malware, the adversary rebrands a powerful open-source tool. They modify PE metadata to mimic a legitimate vendor and use specific HTTP paths to blend in with normal traffic. This hunt provides a structured approach to identifying these bridges within an environment.

### Hypothesis

An intruder has established a persistent, covert tunnel by deploying a customized SoftEther VPN bridge that masquerades as legitimate network monitor software using modified PE metadata and encrypted configuration files.

### How the Hunt Flows

The first phase focuses on scoping via software inventory. The hunt looks for hosts where the software registry contains the fake vendor name "Network Systems Solutions Inc" or the specific SoftEther version 4.44.0.9807 found in the actor's build. Because the adversary may not always register the tool in the official inventory, this step acts as a high-confidence starting point rather than a definitive filter.

The second phase fans out to gather concurrent evidence across multiple surfaces. One query hunts for the persistent service installed by the tool, which often retains the name "sevpnbridge" or points to a binary named netcapa.exe. Simultaneously, the hunt stacks process activity by original file name to find rare instances of netcapa.exe across the fleet. The intruder typically deploys this on a very small subset of systems, making prevalence a strong indicator of unauthorized use.

Next, the hunt searches for the unique configuration file, setting.conf, and masqueraded network traffic. The adversary uses specific HTTP paths like /update/alive.cgi and /update/picture.cgi for C2. While these paths look like standard updates, they represent the custom VPN protocol in transit. The hunt correlates the presence of these network requests with the local file and service artifacts found in the previous steps.

Finally, a triage step brings all findings together. An analyst or agent reviews the host-level results to confirm if the service name, process metadata, and network paths appear together on the same system. This correlation helps distinguish the Webworm toolkit from legitimate, authorized installations of SoftEther or other network monitoring tools.

### Blind Spots

The primary blind spot involves encrypted traffic. If the SoftEther bridge uses HTTPS and the organization does not perform TLS inspection, the specific CGI paths will remain hidden from network activity logs. In such cases, the hunt relies more heavily on endpoint artifacts like the setting.conf file and process metadata. Additionally, if the adversary changes the rebranding strings or binary names in a newer build, the specific metadata filters used in the scoping phase may miss the activity.

### How to Run This Hunt

This hunt is available as a `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any security runtime that supports the open standard. Because this is a hunt, it prioritizes identifying the broader scope of the intrusion over alerting on a single file hash. It identifies the persistence mechanism itself, which provides a more durable signal against modified versions of the SoftEther bridge.

Rapid7 — Spying on Governments with Zero Lines of Malware
