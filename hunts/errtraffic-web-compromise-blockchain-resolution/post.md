# ErrTraffic: Web Compromise and Blockchain C2 Resolution Hunt

The discovery of the ErrTraffic framework by Sekoia (https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework) highlights a significant shift in how ClickFix malware is distributed. Adversaries are no longer relying on static domains; they are leveraging compromised WordPress servers and blockchain-based dead drop resolvers to maintain persistence and bypass reputation-based filtering. This hunt provides a structured way to identify both ends of this infrastructure.

### The Hypothesis
We assume that an adversary has either compromised internal WordPress servers to host malicious payloads or that internal clients are interacting with ClickFix lures that resolve C2 infrastructure via blockchain RPC endpoints. The primary indicators of this activity are unauthorized file modifications on web servers and anomalous DNS traffic from workstations to blockchain infrastructure.

### How the Hunt Flows
The hunt begins by scoping your environment to identify known WordPress instances using software inventory data. This narrows the field for the first detection phase, which examines file activity on these servers. We look specifically for modifications to core files like `index.php` or new files within plugin directories that might serve as backdoors for payload delivery.

Simultaneously, the hunt pivots to the client side. We analyze DNS activity to find rare queries to campaign-specific TLDs such as .beer, .cfd, and .xyz. Because these domains are frequently rotated, simple blocklists are insufficient. Instead, we stack-count these TLDs to find the unique infrastructure used in the current campaign.

To confirm the use of EtherHiding, the hunt monitors for workstations communicating with blockchain RPC providers like Quicknode or Polygon. While common for developers or crypto-enthusiasts, this activity is highly anomalous for general users and serves as a strong corroborator when seen alongside the suspicious TLDs.

Finally, we check HTTP activity for specific delivery paths used by the ErrTraffic JS scripts, such as `/cf.js` or `/api/css.js`. By joining these four surfaces—software, file, DNS, and HTTP—we can distinguish between legitimate browsing and active interaction with the ClickFix distribution framework.

### What the Hunt Cannot See
There are two primary blind spots in this design. First, if a WordPress server does not have an EDR agent with file-level monitoring, we cannot detect the initial payload deployment. Second, while we can see the DNS resolution for blockchain RPC providers, we cannot inspect the specific smart contract queries unless TLS inspection is active and decrypted traffic is analyzed. The hunt relies on the presence of the resolution behavior itself as a high-fidelity signal.

### How to Run It
This design is provided as a `hunt.md` playbook. It can be imported into Huntbase or any hunt.md-aware runtime. Analysts can also manualize the steps by running the included SQL queries against their SIEM or EDR data lakes to identify the relevant events for triage.
