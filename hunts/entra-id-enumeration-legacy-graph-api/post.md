# Hunting for Entra ID Enumeration via the Legacy Graph API

### Why This Hunt Matters

Recent research by Elastic Security Labs, titled [Azure AD Graph Activity Logs: Ingestion and threat detection to close the visibility gap](https://www.elastic.co/security-labs/blog/aad-graph-activity-logs-threat-detection), highlights a persistent security challenge: the legacy Azure AD Graph API. While Microsoft is moving toward the modern Microsoft Graph, the legacy endpoint (`graph.windows.net`) remains active and is frequently targeted by offensive tools for bulk directory enumeration. Because this legacy surface often lacks the same level of default monitoring as its modern counterpart, it serves as a quiet channel for reconnaissance.

### The Hypothesis

We hypothesize that attackers are leveraging tools such as ROADrecon or AADInternals to perform automated directory walkers. These tools often rely on specific, internal API versions (e.g., `1.61-internal`) to extract sensitive directory details that are not as easily accessible through standard calls. Our hunt focuses on finding the intersection of these offensive tools executing on the endpoint and the unique network traffic patterns they generate when talking to the legacy Graph infrastructure.

### How the Hunt Flows

The first phase focuses on scoping. We look for the presence of known enumeration packages in the software inventory. This is a precursor step; while silence here doesn't mean a tool isn't present (as many are run as portable scripts), finding a confirmed installation on a server or developer workstation provides a high-fidelity starting point for the rest of the investigation.

Next, we analyze process activity. We look for command-line arguments that match known offensive functions like `Get-AADInt` or the execution of `roadrecon`. This catches the act of discovery in progress. Because an attacker can easily rename a binary to bypass simple detections, this step is used to feed a broader analysis rather than serve as a standalone alert.

In the final phase, we pivot to network telemetry. This involves a three-pronged analysis: identifying DNS resolutions for the legacy Graph domain, inspecting HTTP requests for the `1.61-internal` version string in the query parameters, and stack-counting User-Agents. We are specifically looking for rare or non-standard libraries—like `aiohttp` or `python-requests`—targeting the Graph API, which are common signatures of scripted offensive tooling in environments where first-party Microsoft clients usually dominate.

### What This Hunt Cannot See

This hunt has two primary blind spots. First, if your network does not perform HTTPS inspection or your EDR does not capture full URI query strings for encrypted traffic, you will miss the specific `api-version` indicators. In those cases, you must rely more heavily on the User-Agent stacking and process-level correlations.

Second, this hunt is endpoint-centric. It cannot see what the server-side response was or what specific objects were exfiltrated. For that level of detail, you must enable `AzureADGraphActivityLogs` in your Entra ID Diagnostic Settings. Without those logs, we can identify that enumeration occurred, but the full scope of the data loss remains opaque.

### How to Run It

This hunt is provided as a `hunt.md` playbook. This is an open, machine-readable format for threat hunting. You can import this playbook directly into Huntbase or any other `hunt.md`-aware runtime. The playbook will guide you through the queries, the automated triage steps, and the necessary containment actions if malicious activity is confirmed.
