# Hunting DPRK Ted Backdoor and CurlRAT on HAProxy Load Balancers

Rapid7 recently detailed DPRK APT activity targeting South Korean organizations using the Ted backdoor and CurlRAT in [DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors). These tools allow adversaries to intercept web traffic at the load balancer and establish remote access to internal systems. This hunt provides a structured way to identify these artifacts across Linux-based edge infrastructure.

### The Hypothesis
An adversary compromises the edge load balancer by installing a custom HAProxy filter and a Curl-based RAT to intercept web traffic and execute remote commands. This activity bypasses standard host-based protections by residing within the proxy process and using common utilities for exfiltration.

### Scoping the Environment
The first phase identifies Linux hosts running HAProxy 2.8.12. This specific version serves as the foundation for the Ted backdoor plugin. Because the backdoor relies on a custom filter compiled for this version, isolating these hosts narrows the hunt surface to systems that meet the technical requirements for the observed toolkit. If an environment uses different versions or does not run HAProxy, the probability of this specific campaign being present is low.

### Parallel Investigation of C2 and Artifacts
Once the hunt identifies relevant hosts, it initiates three parallel queries to gather evidence from network and host activity. The first query searches for HTTP requests to known CurlRAT command-and-control domains, such as `img.darklights.store`. This activity indicates that the RAT is active and attempting to retrieve instructions or post stolen data.

Simultaneously, the hunt monitors the network behavior of the HAProxy process. A second query looks for the proxy process or its children initiating outbound connections to public IP addresses. Legitimate load balancers typically communicate with internal backends or specific management IPs; direct outbound connections to the public internet suggest C2 traffic or exfiltration. 

Finally, the hunt baselines file activity for the proxy process. The third query flags rare file writes by HAProxy to system library directories like `/usr/lib/` or variable directories like `/var/lib/`. The Ted backdoor framework often places malicious filters or encrypted log files in these locations to remain persistent and hide collected credentials.

### Synthesis and Triage
An analyst evaluates the combined results of the scoping and investigation phases. A host showing the target HAProxy version alongside suspicious network connections or unusual file modifications receives a malicious verdict. This correlation is essential because the individual behaviors—such as an outbound connection or a file write—might appear benign in isolation but become high-confidence indicators when occurring together on a critical edge appliance.

### Blind Spots and Limitations
This hunt relies on host and network logs. If edge proxies do not log custom HTTP headers, the hunt cannot confirm the presence of the 'User-token' header unique to CurlRAT, which increases the risk of false positives from shared infrastructure. Furthermore, if the adversary loads the Ted backdoor filter directly into memory without leaving a persistent binary on disk, standard file audit logs will not capture the installation. In such cases, memory forensics or binary integrity monitoring for load balancer executables is required to confirm the compromise.

### Running the Hunt
This hunt is a `hunt.md` playbook that imports into Huntbase or any hunt.md-aware runtime. It uses a funnel approach, starting with software inventory scoping before moving into behavioral analysis. Practitioners should run the scoping query first to identify the relevant edge footprint before executing the parallel investigation steps.
