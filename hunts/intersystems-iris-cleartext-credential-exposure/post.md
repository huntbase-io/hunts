# InterSystems IRIS Cleartext Credential Exposure and Access

### Why this hunt

InterSystems IRIS for Health is a backbone for healthcare data, managing electronic health records and laboratory information. CISA Advisory ICSMA-26-295-01 (https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-295-01) describes a significant vulnerability where the platform's superserver transmits credentials in cleartext by default on port 1972. While a simple detection might flag an old version, this hunt focuses on the behavioral bridge between that vulnerability and a successful breach. The process looks for unencrypted traffic and the subsequent unauthorized login that indicates an attacker exploited the exposure.

### The Hypothesis

An attacker intercepts cleartext credentials from InterSystems IRIS superserver traffic on port 1972 to gain unauthorized access to the environment. This activity manifests as unencrypted network flows from external or unexpected IPs followed by successful authentication events on the target host using those same source IPs. We assume that if an adversary can see the traffic, they capture the credentials and use them immediately to establish a foothold.

### How the hunt flows

The hunt starts by scoping the estate. A query against software inventory identifies every host running affected versions of InterSystems IRIS for Health. This step creates a targeted list of systems to prevent running expensive global network queries across the entire network. If the inventory returns no results, the hunt concludes early to save analyst time and processing resources.

Once an analyst confirms the presence of vulnerable hosts, the hunt launches two parallel investigations. The first query examines network connections on the default IRIS superserver port 1972. It aggregates traffic volume, byte counts, and source IPs to find unusual unencrypted communication. The hunt baselines this traffic to find new or rare source IPs that have not historically managed these systems.

At the same time, a second query pulls successful sign-in logs from the security event surface for those specific IRIS hosts. This allows the team to see who logs in and from where during the period of unencrypted traffic. The hunt looks for interactive and network-level logons that occur shortly after or during the identified network traffic spikes.

Finally, the hunt uses an automated agent to synthesize these findings. The agent correlates the source IPs seen in the superserver traffic with the source IPs recorded in the authentication logs. This correlation identifies logins that likely used intercepted credentials. Instead of manual triage, the agent provides a per-host verdict. An analyst then reviews this synthesis to separate legitimate administrative management from malicious access. This ensures that only high-confidence leads move to the isolation and containment phase.

### What this hunt cannot see

Visibility depends entirely on EDR coverage across the clinical environment. If a medical device or legacy server lacks an agent or does not report software inventory, the hunt misses that host entirely. Furthermore, the hunt focuses on OS-level authentication logs. Logins that occur strictly inside the InterSystems IRIS application database—and do not trigger a system-level sign-in event—stay invisible to the current OS-based queries. This is a common blind spot in specialized medical software where internal databases manage their own user sets. Finally, without network flow data or host-based network telemetry for port 1972, identifying the specific traffic spikes that precede a login is impossible.

### How to run it

This hunt is an open hunt.md playbook. You can import it directly into Huntbase or any runtime that supports the hunt.md standard. Once imported, you provide the list of vulnerable versions from the CISA advisory and set your lookback window to begin the scoping phase. The playbook handles the transitions between software inventory, network traffic analysis, and authentication correlation automatically. Analysts review the final synthesized findings to determine if immediate host isolation is necessary.
