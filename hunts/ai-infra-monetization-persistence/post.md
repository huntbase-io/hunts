# Hunting Host Persistence and Monetization in Compromised AI Infrastructure

### Why this hunt
Microsoft's recent analysis, [When AI infrastructure becomes the target: Securing gateways and control points](https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/), details how attackers exploit AI management layers. Once inside, an adversary rarely stays within the application. They move to the host to monetize compute resources or solidify access. This hunt provides the steps to find that transition.

### Hypothesis
An attacker has compromised an AI gateway or retrieval engine and is now deploying masqueraded payloads to monetize the host via cryptomining and establish durable SSH or systemd persistence.

### How the hunt flows
The first query scopes the environment using `hb_software_inventory`. The analyst identifies Linux hosts running specific AI software such as LiteLLM, RAGFlow, or Kestra. This establishes the target population before looking for behavioral anomalies.

The hunt then pivots to `hb_process_activity` to find masqueraded binaries. It uses a prevalence baseline to highlight processes executing from world-writable paths like `/tmp` or `/dev/shm` that appear on only a few hosts. Simultaneously, the hunt looks for environment fingerprinting commands like `sudo -l` or `crontab -l` launched directly from AI gateway parent processes.

Next, the analyst examines indicators of host abuse and persistence. A query on `hb_module_activity` searches for the `msr` module, which attackers load to tune CPUs for cryptomining. Another query checks `hb_file_activity` for unauthorized modifications to SSH `authorized_keys` or systemd service files. An analyst also uses `hb_process_activity` to detect credential harvesting by searching for commands reading `/proc/1/environ` or environment variables like `DATABASE_URL` and `API_KEY`.

Finally, the hunt uses an agent triage step to synthesize these findings. The agent correlates the presence of rare binaries with the follow-on discovery and persistence activity to provide a final verdict. If the analyst confirms a compromise, they proceed to isolate the host and perform a forensic review of the modified configurations.

### What the hunt cannot see
This hunt has three primary blind spots. First, it cannot determine if the `msr` module was loaded with `allow_writes=1`, which is the specific setting required for mining optimization. Second, short-lived payloads that execute and terminate between snapshots may not appear in process telemetry depending on the data source frequency. Third, while we detect modifications to SSH keys, we cannot see the actual public key content being added, which prevents immediate attribution without further host-level forensics.

### How to run it
This hunt is an open `hunt.md` playbook. It imports into Huntbase or any other `hunt.md`-aware runtime. Use the provided parameters to adjust the lookback window or add specific AI application names relevant to your environment. The hunt runs in two main phases: an initial read of delivery and discovery signals, followed by a deeper dive into impact and persistence indicators.
