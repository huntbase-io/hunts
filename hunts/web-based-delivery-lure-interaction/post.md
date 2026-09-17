# Hunting for Malicious Google Doc Sidebars and ClickOnce Installers

### Why This Hunt Matters

Recent reporting from Huntress in their article [Post-DEF CON Phishing Uses Malicious Google Doc to Deliver Malware](https://www.huntress.com/blog/defcon-phishing-google-doc-malware) highlights a sophisticated delivery chain targeting security practitioners. The campaign uses a malicious Google Doc sidebar to trick users into downloading and executing malware, specifically the AMOS or NetSupport RATs. This hunt is designed to catch the delivery before these payloads establish themselves on an endpoint.

### The Hypothesis

We hypothesize that we can identify this campaign by looking for the specific artifacts of the delivery mechanism: the loading of a malicious HTML sidebar called `DecryptPanel.html` and the execution of a ClickOnce installer manifest named `GapiUpdate.application`. These files and their associated domains are uncommon enough to stand out when stacked against normal fleet activity.

### How the Hunt Flows

The hunt begins by scoping the environment to Windows and macOS hosts, as the campaign delivers platform-specific payloads. We focus our initial search on the most vulnerable surfaces for this delivery method.

Next, we examine HTTP activity for interaction with the lure components. We look specifically for the HTML and .application file names in URL paths and query strings. This stage is intended to find the moment a user interacts with the malicious Google Doc sidebar or triggers the ClickOnce download.

To increase our confidence, we pivot to DNS telemetry. We check for successful resolutions to the specific domains used to host the lures and payloads. By correlating these resolutions with the HTTP traffic, we can confirm that the host is actively communicating with the attacker's infrastructure rather than simply viewing a cached page.

Finally, we perform a fleet-wide stack-count of .application file executions. ClickOnce is a legitimate Windows technology, but its use for third-party tools is often limited. By looking for .application files that appear on a very small number of hosts, we can isolate the specific malicious installer used in this phishing campaign from routine software updates.

### Blind Spots and Limitations

The primary blind spot for this hunt is TLS encryption. If the organization does not perform HTTPS inspection via a proxy, the specific URL paths like `DecryptPanel.html` will remain hidden within the encrypted tunnel. In such cases, we must rely more heavily on DNS resolution and process command-line artifacts.

Additionally, if endpoint logging truncates command lines for interpreters like `dfsvc.exe`, we may lose visibility into the manifest URL being executed. It is critical that process logging captures the full execution context to identify the rogue manifest.

### How to Run This Hunt

This hunt is provided as a `hunt.md` playbook. It is a machine-readable format that can be imported directly into Huntbase or any other hunt.md-aware runtime. It uses standardized queries to pull telemetry from common surfaces, allowing for a structured, repeatable analysis of the phishing delivery chain.
