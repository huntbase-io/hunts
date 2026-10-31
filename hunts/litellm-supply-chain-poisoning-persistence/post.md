# Hunting for Poisoned LiteLLM Packages and Python Persistence

### Why This Hunt Matters
ESET Research recently detailed several supply chain attacks in their Lessons from Cybersecurity Black Week (https://www.welivesecurity.com/en/business-security/lessons-cybersecurity-black-week/) report. One specific threat involves a poisoned version of the LiteLLM library, version 1.107.0. This malicious package contains code designed to establish persistence and exfiltrate sensitive host credentials. Because adversaries can rename packages or modify version strings, relying solely on package inventory lists is insufficient.

### The Hypothesis
An adversary installs a poisoned version of the LiteLLM library to establish persistence via Python startup files and exfiltrate host credentials from the environment.

### How the Hunt Flows
The hunt starts with a scoping phase focused on process history. It searches for pip installation commands or execution strings that contain the specific malicious version string. This identifies which hosts attempted the installation, capturing activity even on ephemeral build agents that might no longer be active in the current fleet inventory.

Once an analyst or automated agent confirms a valid lead, the hunt gates into a parallel deep-dive. One branch stacks .pth files across the environment. Malicious Python packages frequently drop these files into site-packages directories to hijack the Python startup process. By looking for files that appear on fewer than five hosts, the hunt isolates custom persistence mechanisms from legitimate library files.

Simultaneously, the hunt monitors for Python processes accessing sensitive file paths. It specifically looks for reads of AWS credentials, SSH private keys, and Docker configuration files. This behavioral signal confirms if the poisoned package has begun its primary objective of credential theft.

In the final phase, an agent correlates the initial installation lead with the observed persistence and file access patterns. This multi-surface approach allows for a high-confidence verdict. If a host shows the malicious package alongside rare .pth files or unauthorized secret access, the hunt triggers host isolation to stop the exfiltration.

### Blind Spots and Limitations
This hunt relies heavily on process command-line auditing. If a host lacks process telemetry, the initial scoping query will not see the installation event. Furthermore, the file access monitoring targets standard paths for cloud and shell secrets. If an adversary targets non-standard credential stores or custom application secrets, the behavioral queries will not observe the theft.

### How to Run It
This hunt is provided as a hunt.md playbook. It is designed to be imported into Huntbase or any hunt.md-aware runtime. This format allows the hunt to handle the gated logic and parallel queries automatically, moving from a broad lead to specific containment actions without manual data shuffling.
