# Hunting APT28 Edge Hijacking and AI-Based Exfiltration

### Why this hunt
Sekoia recently published "APT28: An Evolution of Tradecraft from X-Agent to LLM Malware" (https://www.sekoia.com/blog/apt28-an-evolution-of-tradecraft), which describes how the actor evolved from custom implants like X-Agent to using compromised edge devices and AI-integrated malware. This hunt targets the specific behavioral intersections of these modern techniques.

### Hypothesis
An adversary hijacks local DNS settings via compromised edge infrastructure and uses a rare, non-browser process to automate the harvesting of documents for exfiltration via AI APIs or high-port tunnels.

### DNS Hijacking and Edge Manipulation
The hunt begins by identifying anomalies in DNS resolution. When an adversary compromises an edge device like a SOHO router, they often redirect DNS traffic. This frequently breaks internal resolution while external connectivity remains. The first query identifies hosts where internal domain lookups consistently return NXDOMAIN errors, but external lookups succeed. This discrepancy is a primary scoping signal for potential edge infrastructure tampering.

### Automated Document Harvesting
Once an adversary gains a foothold, they use automated tools to find and stage data. The hunt identifies processes that access an unusual volume of sensitive file types, specifically Word documents, PDFs, and text files. It filters for a single process reading over 100 unique files within a one-hour window. This threshold distinguishes automated harvesting from typical user activity, where a user might open several files but rarely hundreds in rapid succession.

### AI-Based Exfiltration and Tunnels
Modern infostealers increasingly use legitimate AI services for data processing or as a channel for command generation. The hunt searches for connections to domains such as api.openai.com or api.anthropic.com originating from processes that are not standard web browsers. Additionally, it checks for high-port outbound traffic on ports 1080, 8080, or above 10000, which are common markers for the X-Tunnel proxy tool used by APT28 for lateral movement and exfiltration.

### Agent Correlation and Triage
The hunt concludes with an agent-based triage step. Instead of treating these signals as isolated alerts, an agent correlates the DNS anomalies with the document harvesting and network activity. It identifies hosts where all three behaviors overlap. This provides a high-confidence verdict by confirming that a host with hijacked DNS is also running a rare process that reads many documents and communicates with suspicious external endpoints.

### What the hunt cannot see
This hunt has specific limitations. If an edge router rewrites DNS responses at the packet level, the local operating system logs might show a successful resolution from its expected upstream, masking the hijack. Furthermore, the hunt identifies connections to AI APIs but cannot see the specific data sent in the request body without TLS decryption. Legitimate business tools that incorporate LLMs may also generate false positives requiring manual verification.

### How to run it
This hunt is a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to run it across your fleet. It is designed for periodic execution to identify long-running exfiltration campaigns that bypass traditional real-time detection signatures.
