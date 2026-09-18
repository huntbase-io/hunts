# Hunting Certutil Payload Delivery and PowerShell Execution

### Why Now

The industry is shifting toward more structured, agentic approaches to security operations. As discussed by Elastic Security Labs in [Why 2026 is the Year to Upgrade to an Agentic AI SOC](https://www.elastic.co/security-labs/blog/why-2026-is-the-year-to-upgrade-to-an-agentic-ai-soc), the future of detection lies in moving beyond static alerts and toward automated reasoning across multiple telemetry surfaces. This hunt design reflects that shift, using a logic-heavy approach to investigate LOLBin abuse that would typically require significant manual analyst time.

### The Hypothesis

We hypothesize that attackers are leveraging internet-facing web assets to gain initial access, subsequently using `certutil.exe` to download malicious payloads. To avoid detection, they use specific flags like `-urlcache` or `-split` and then execute the final stage via PowerShell. By focusing on the behavior of the download and the subsequent execution rather than just the file hashes, we can identify staging activity that evades traditional controls.

### How the Hunt Flows

The first phase is a scoping exercise. We use the `hb_software_inventory` surface to identify hosts running common web services such as Apache, Nginx, or IIS. These assets represent the most likely entry points for web-based exploitation and provide the initial context for the rest of the investigation.

Next, the hunt generates leads by looking for proxy execution via `certutil.exe`. We monitor `hb_process_activity` for instances where certutil is invoked with download-related flags. This query is designed to catch the activity even if the binary has been renamed, ensuring we don't miss attackers attempting to hide their tracks by modifying filenames.

Once a lead is identified, the hunt enters a corroboration phase across three independent surfaces. It checks `hb_dns_activity` for lookups to known or suspicious C2 domains, searches `hb_script_activity` for rare PowerShell script blocks containing obfuscation or Base64 encoding, and examines `hb_http_activity` for signs of inbound exploit attempts. This multi-surface approach allows us to distinguish between legitimate maintenance and a coordinated attack.

### Blind Spots and Limitations

No hunt is exhaustive. This playbook relies heavily on endpoint visibility; if a web-facing asset is not reporting process or script telemetry to your EDR, it remains a blind spot. Additionally, while we can see the metadata of inbound HTTP requests (such as paths and query strings), we lack visibility into the full request bodies. This means we may see the attempt to exploit a vulnerability, but not the specific shellcode or script content delivered within a POST request.

### How to Run This Hunt

This hunt is packaged as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime environment that supports the `hunt.md` standard. The parameters allow you to specify custom C2 domains and lookback periods, making it adaptable to both specific threat intelligence and general hygiene checks.
