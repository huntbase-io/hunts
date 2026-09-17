# Hunting for AD RMS Root Key Discovery and Extraction

The security of Microsoft Active Directory Rights Management Services (AD RMS) hinges on a specific root key known as the Server Licensor Certificate (SLC). As detailed in the Huntress research [AD Rights Management Service (Part 2): Extraction, Offline Decryption, and the Unrotatable Key](https://www.huntress.com/blog/ad-rms-slc-encryption-key), this key often has a 255-year lifespan and cannot be rotated without re-protecting every single document in the organization. If an attacker extracts this key, they gain the ability to decrypt protected data offline, indefinitely.

### The Hypothesis
We hypothesize that an intruder, having compromised an AD RMS Service Group account, is attempting to discover the cluster configuration and extract the SLC private key. This may be performed via Trusted Publishing Domain (TPD) exports or direct access to the SQL backend hosting the configuration database. Because these actions often mirror legitimate administrative tasks, we cannot rely on a single detection; we must instead look for the flow of discovery leading to extraction.

### How the Hunt Flows
The hunt begins with a scoping phase using software inventory surfaces. We identify the specific hosts running AD RMS and the associated SQL Server instances. Narrowing the scope here is critical to reduce noise and focus our subsequent analysis on the high-value infrastructure where the SLC actually resides.

Once the infrastructure is mapped, we look for process execution behavior. Specifically, we search for command-line arguments associated with discovery and extraction tools such as SharpRMS or the use of the `keyprotection` command. We apply a prevalence filter to these findings, stacking the tools across the fleet to identify rare or unauthorized usage on the identified RMS servers.

In the enrichment phase, we pivot to authentication and network telemetry. We examine sign-in events to the RMS infrastructure to find non-standard actors or anomalous timing. Simultaneously, we analyze network connections to the administrative SOAP ports (typically 80 or 443) on those servers. By filtering out common browser processes, we can isolate scripts, PowerShell, or custom binaries communicating with the RMS web services.

Finally, the hunt uses an agent to correlate these overlaps. A verdict is reached by weighing the presence of discovery commands against unusual authentication and non-browser network traffic to the RMS administrative surface.

### Blind Spots and Limitations
This hunt has two primary blind spots. First, it lacks visibility into the specific SOAP payloads being transmitted over HTTPS. Without TLS decryption or AD RMS server-side audit logs, we cannot distinguish between a legitimate administrative export and a malicious one based on the network packet alone. Second, the hunt does not inspect file magic on the wire, meaning we cannot see if an attacker is sweeping the network for protected OLE compound files.

### How to Run This Hunt
This hunt is provided as an open-source `hunt.md` playbook. It can be imported directly into Huntbase or any other `hunt.md`-aware runtime. Practitioners should begin by populating the infrastructure list to ensure the pivots accurately target their specific RMS deployment.
