# Hunting SonicWall SMA Zero-Day Proxy Bypass and WebSocket Tunneling

Volexity recently published research, [Proxying to Compromise: SonicWall SMA 0-day Exploitation](https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/), detailing how adversaries are exploiting a zero-day vulnerability in SonicWall SMA 1000 series appliances. The vulnerability allows for an unauthenticated proxy bypass, which attackers use to establish persistent WebSocket tunnels into the internal management services of the device. This hunt design focuses on identifying the specific behavioral footprints left during this initial access and tunneling phase.

### The Hypothesis
We hypothesize that an adversary is utilizing a crafted User-Agent and specific URL paths to trigger a 101 Switching Protocols response on the `/wsproxy` endpoint. Successful exploitation results in the appliance's web server processes (such as nginx or httpd) establishing unexpected loopback connections to local management ports like CouchDB or the SMA Control Service, effectively bypassing intended access controls.

### How the Hunt Flows
The first phase of this hunt establishes the search space by identifying vulnerable hardware. We scope the investigation to SonicWall SMA models 6210, 7210, and 8200v by querying the software and hardware inventory. This ensures that the subsequent high-volume telemetry queries are focused on the correct assets, reducing the performance impact on the logging infrastructure.

Once the targets are identified, the hunt looks for the primary indicator of the proxy bypass: HTTP 101 status codes. We specifically filter for requests to the `/wsproxy` path where the User-Agent is set to 'SMA Connect Agent'. While this User-Agent is legitimate, its association with a protocol upgrade to a management endpoint is a high-fidelity signal for investigation, especially when originating from unexpected source IPs.

To confirm that the bypass was successful and used for tunneling, the hunt pivots to host-level network telemetry. We look for loopback connections (127.0.0.1) originating from the web server processes (nginx, httpd) and terminating on internal management ports including 1050, 1051, and 8188. This correlation is the core of the hunt; a protocol upgrade followed immediately by internal management traffic from the web server suggests an active tunnel is being used by an external actor.

Finally, we perform a frequency analysis on the source IPs associated with the SMA Connect Agent string. By stack-counting these IPs across the fleet, we can isolate rare or anomalous sources. Legitimate traffic typically follows a predictable pattern of known user IPs, whereas attacker-controlled infrastructure often appears as a statistical outlier with a low host-count but high request volume.

### Blind Spots and Limitations
This hunt relies heavily on the visibility of loopback interface traffic. Many EDR and host-monitoring tools filter out connections to 127.0.0.1 by default to reduce noise. If your environment does not capture internal process-to-process networking on the appliance, you will be limited to identifying the bypass attempt via HTTP logs without confirmation of successful tunneling. Additionally, if the appliance logs are processed by a middlebox that strips query parameters, the specific bypass string ('bmID=-3389') may be lost, forcing a reliance on the status code and User-Agent alone.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any security platform that supports the hunt.md-aware runtime. By following the structured steps, analysts can automate the scoping and detection phases while retaining manual control over the final triage and isolation decisions. The hunt design includes specific logic for isolating affected appliances if exploitation is confirmed. This is a hunt, not a static detection, because it requires the correlation of disparate telemetry types—HTTP, process, and network—to differentiate legitimate administrative activity from unauthorized tunneling.
