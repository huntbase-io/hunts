# Hunting for AD RMS Master Key Extraction and Offline Decryption

### Why This Hunt Matters

This playbook addresses a critical failure point in Active Directory Rights Management Services (AD RMS) identified by the research in AD Rights Management Service (Part 2): Extraction, Offline Decryption, and the Unrotatable Key (https://www.huntress.com/blog/ad-rms-slc-encryption-key). The Server Licensor Certificate (SLC) key is the root of trust for an entire RMS cluster. If an intruder exports this key, they gain the ability to decrypt any document protected by that cluster. Because this key is unrotatable and valid for centuries, the only defense is detecting the extraction and the subsequent unauthorized decryption activity.

### The Hypothesis

An intruder extracts the AD RMS SLC private key through a Trusted Publishing Domain (TPD) export and uses it to decrypt protected documents offline. The adversary first performs discovery to confirm if the key is software-based before making SOAP-based web requests to the administrative endpoints to facilitate the export.

### How the Hunt Flows

The hunt begins with a scoping phase to identify every host running AD RMS software. The playbook queries software inventory logs for Rights Management packages or Microsoft RMS components. This step allows the analyst to narrow the focus of subsequent, more intensive telemetry searches to the specific servers capable of hosting the SLC key.

Once the servers are identified, the hunt runs two searches in parallel to find evidence of extraction. The first search looks for successful HTTP 200 OK responses to specific AD RMS administrative SOAP endpoints, such as server.asmx or trustpolicy.asmx. These endpoints handle the TPD export process. The second search looks for discovery tools like SharpRMS or the use of the keyprotection command in process command-line logs, which indicate an adversary is auditing the key protection level.

An analyst or automated agent then correlates these signals. If a host shows both administrative SOAP activity and discovery-related process execution, the hunt marks it for a high-confidence extraction attempt. The hunt then pivots away from the RMS servers to the entire fleet to baseline decryption activity. It looks for rare process execution involving flags like --decrypt or --slc, which are common in offline decryption tools. By filtering for commands that appear on three or fewer hosts, the hunt surfaces unauthorized data access that does not match standard administrative behavior.

### Blind Spots and Limitations

This hunt relies heavily on endpoint and web server telemetry. If an adversary runs discovery tools on a device not enrolled in monitoring, the process-level signals will not trigger. Furthermore, because the SLC key allows for completely offline decryption, the hunt cannot see decryption activity if the attacker moves the stolen documents and the SLC key to an unmanaged, personal machine. Finally, the hunt does not identify the initial reconnaissance phase where an attacker sweeps file shares for RMS-protected content, as identifying specific OLE magic bytes requires deep file inspection beyond standard file activity logs.

### How to Run This Hunt

This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the logic across your estate. The playbook includes the SQLite queries for software inventory, HTTP activity, and process logs. To start, run the scoping query to populate the server list and then proceed through the parallel extraction and fleet-wide decryption baseline steps.
