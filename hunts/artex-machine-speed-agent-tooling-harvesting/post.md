# Hunting ARTEX Agentic AI Tooling and Machine-Speed Credential Harvesting

### Why this hunt
In the report "What defenders need to know about ARTEX, the agentic AI framework threat actors abuse" (https://www.microsoft.com/en-us/security/blog/2026/11/25/what-defenders-need-to-know-artex-agentic-ai-framework-threat-actors-abuse/), Microsoft describes a shift toward autonomous agentic attacks. The ARTEX framework uses a Go-based backend to orchestrate LLM agents that execute offensive tools in rapid succession. This allows adversaries to perform reconnaissance and move laterally at speeds that exceed human intervention. This hunt provides a structured approach to identifying the endpoint telemetry left behind by this high-speed automation.

### The Hypothesis
An automated agent performs high-frequency tool execution to conduct reconnaissance and dump credentials from sensitive files like .env or /etc/shadow at machine speeds.

### How the Hunt Flows
The first phase of the hunt searches the `hb_process_activity` surface for offensive tools explicitly mentioned in the ARTEX report. The query looks for binaries such as sqlmap, hydra, and netcat across all directory paths. This step acts as the primary lead, identifying hosts where known penetration testing tools are active.

Once we identify tool use, the hunt parallelizes the investigation to corroborate the "machine-speed" signature. We baseline the use of common interpreters like Node.js, Python, and PowerShell. The query identifies hosts running a burst of more than 20 commands through these interpreters within a single one-hour window. While legitimate CI/CD pipelines often produce high-frequency launches, we correlate this activity with the next two signals to reduce noise.

The hunt simultaneously inspects `hb_file_activity` for access to sensitive credential stores. The process targets environment files like .env and operating system files like /etc/shadow or passwd. At the same time, we check `hb_dns_activity` for outbound queries to webhook.site and other exfiltration domains used by ARTEX for script delivery or data return.

In the final phase, an automated agent triages the combined telemetry. The agent evaluates the proximity of tool execution, the frequency of interpreter use, and the specific files accessed. This helps an analyst distinguish between standard developer automation and the behavior of an autonomous framework.

### Blind Spots
This hunt has two primary blind spots. First, standard endpoint monitoring may not capture access to restricted files like /etc/shadow unless the system is specifically configured for root-level file auditing. Second, because ARTEX agents use dynamically generated scripts, the exact intents of the agent remain obscured without full script block logging in `hb_script_activity`.

### Running the Hunt
This hunt is provided as a `hunt.md` playbook. It imports directly into Huntbase or any compatible hunt.md-aware runtime. Analysts should tune the `lookback_days` and `artex_tools` parameters to fit their specific environment.
