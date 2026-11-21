# Identifying Compromised End-of-Life IoT Devices via Network Telemetry

### The Risk of Abandoned Hardware

End-of-life (EoL) IoT devices represent a significant blind spot in modern networks. As ESET Research notes in their article, [My IoT devices are no longer supported – is my smart home safe?](https://www.welivesecurity.com/en/internet-of-things/iot-devices-no-longer-supported-smart-home-safe/), these devices often continue functioning long after manufacturers stop providing security patches. Without updates, they become easy targets for botnet operators and traffic redirection schemes.

### The Hypothesis

Adversaries conscript end-of-life IoT devices into botnets or hijack them for traffic redirection. This compromise manifests as anomalous DNS failure patterns, internal lateral probing, or HTTP connections to phishing infrastructure. Since these devices lack endpoint agents, the network interface is the only reliable surface for detection.

### How the Hunt Flows

This hunt does not begin with broad, expensive scanning. Instead, it uses a gated flow to identify high-confidence leads before investigating specific behaviors.

First, a lead query examines the `hb_dns_activity` surface. The query seeks internal IP addresses generating a high volume of NXDOMAIN or SERVFAIL responses. This pattern often indicates a botnet agent attempting to reach command-and-control (C2) servers via Domain Generation Algorithms (DGA) where the domains have not yet been registered or have already been taken down.

Once an analyst confirms these DNS leads, the hunt gates the next phase. If the behavior looks automated rather than accidental, the hunt pivots into parallel behavioral analysis. It searches the `hb_network_connection` surface for internal management port probing—such as Telnet or ADB—directed at multiple internal targets. Simultaneously, it checks the `hb_http_activity` surface for connections to known phishing or redirection domains, which suggests the device is acting as a malicious gateway.

Finally, the analyst correlates these findings. A device showing both C2-style DNS failures and internal scanning is a high-confidence candidate for isolation. 

### What This Hunt Cannot See

This hunt focuses on the L3 gateway level. If an adversary moves laterally between two devices on the same L2 subnet without passing through a monitored router or switch, the network connection queries will not see the traffic. Additionally, if the botnet uses DNS-over-HTTPS (DoH) to hide its lookups, the lead DNS query will remain silent, forcing the hunt to rely entirely on the later behavioral steps. Identifying the specific physical device also requires accurate asset management or MAC OUI data, which may be missing in unmanaged environments.

### Why This Is a Hunt, Not a Detection

While a single rule might catch a static malicious domain, this hunt identifies the pivot from C2 failures to internal lateral movement across multiple telemetry surfaces. It uses a gated flow to manage the cost of behavioral queries and requires an analyst to confirm the automated nature of the traffic before proceeding to containment.

### How to Run It

This hunt is provided as a `hunt.md` playbook. You can import it into Huntbase or any `hunt.md`-aware runtime. It targets standard network telemetry surfaces and can be scoped to specific IoT VLANs or guest networks to reduce noise from enterprise IT equipment.
