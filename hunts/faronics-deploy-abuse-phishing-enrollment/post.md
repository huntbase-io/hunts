# Hunting Rogue Faronics Deploy Enrollments and Masqueraded Binaries

Adversaries are increasingly leveraging the trust inherent in signed, legitimate management software to bypass traditional security controls. A recent investigation by Huntress, [Daisy-Chaining Trust: Investigating Faronics Deploy Abuse](https://www.huntress.com/blog/faronics-deploy-abuse), details a campaign where attackers use the Faronics Deploy agent to establish a beachhead. This hunt operationalizes that research into a structured process for identifying rogue enrollments within your environment.

### The Hypothesis
Our hypothesis is that an adversary has successfully enrolled endpoints into a rogue Faronics Deploy tenant. They achieve this by tricking users into executing signed Faronics binaries that have been renamed to mimic common business applications like Adobe Acrobat or Zoom. Once executed, these agents connect back to an attacker-controlled Faronics instance, allowing the adversary to push scripts and payloads with administrative privileges.

### How the Hunt Flows
The hunt begins by establishing a baseline of authorized Faronics installations. By querying software inventory, we identify where the software is expected to reside. This provides the necessary context for later triage, allowing analysts to quickly spot installations on high-value or unusual endpoints, such as executive workstations, that do not typically require this management tool.

Next, the hunt looks for evidence of the initial compromise chain. We examine network traffic for specific profiling domains and URL parameters, such as the `verified=1` flag used by the attackers to fingerprint visitors before delivery. This step helps correlate external traffic with subsequent execution events on the endpoint.

We then focus on masquerading. We search for processes where the file metadata identifies the vendor as Faronics, but the actual process name or original file name has been altered to something innocuous, like `Adobe.exe` or `Invoice.exe`. This is a high-fidelity indicator of the social engineering campaign described in the source research.

Finally, we stack-count the 'ck' (customer/deployment) identifiers in HTTP requests directed to `deploy.faronics.com`. By grouping these identifiers and counting the number of associated hosts, we can isolate rare IDs. A 'ck' ID that only appears on one or two hosts, especially when those hosts also show signs of phishing redirection, is a strong candidate for a rogue tenant enrollment.

### Limitations and Blind Spots
This hunt has two primary blind spots. First, if the environment lacks TLS inspection, we may not be able to see the specific query parameters like `verified=1` or the `ck` identifiers within encrypted HTTP traffic. In such cases, the hunt relies on domain-level visibility and process-based masquerading detection. Second, if an attacker uses the agent for a quick 'smash and grab' operation—deploying a secondary payload and then immediately uninstalling Faronics—the software inventory may not capture the event, leaving only process and network logs behind.

### Running the Hunt
This hunt is provided as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime that supports the `hunt.md` standard. The playbook includes the specific SQLite queries needed to surface these artifacts across your telemetry. Because Faronics is a legitimate tool, this is not a binary detection; it requires an analyst to weigh the resulting evidence against known-good administrative practices.
