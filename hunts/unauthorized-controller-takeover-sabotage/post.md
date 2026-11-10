# Hunting for Danfoss Controller Takeover and Parameter Sabotage

### Why Now

Recent reporting by Sekoia in [The Cold Chain on Fire: Unpatched Danfoss controllers exploited](https://www.sekoia.com/blog/the-cold-chain-on-fire-unpatched-danfoss-controllers-exploited) details active exploitation of refrigeration controllers. Adversaries target unauthenticated CGI endpoints to rename administrative accounts and reset passwords. Once they gain access, attackers modify operational parameters such as temperature setpoints and defrost cycles, leading to potential food spoilage and equipment damage. This hunt provides a way to verify if your internet-exposed OT assets have been targeted.

### The Hypothesis

An attacker hijacks administrative accounts on refrigeration controllers via unauthenticated CGI endpoints to sabotage operational parameters like temperature and defrost cycles. This hijacking occurs primarily through the xml.cgi interface, where unauthenticated requests permit critical configuration changes.

### How the Hunt Flows

The hunt begins by inventorying the estate. The first query searches exposed asset data to identify any Danfoss controllers reachable from the internet. This step builds the target list for subsequent traffic analysis, ensuring the hunt focuses on the relevant attack surface.

Next, the hunt performs a parallel analysis of HTTP activity. One branch looks for known malicious IP addresses from the Sekoia report while searching for specific OT-centric verbs in URL query strings, such as 'rename', 'set_temp', or 'defrost'. The second branch baselines external IP addresses to find rare sources that interact with only one or two controllers, bypassing standard management subnets.

An analyst or automated agent then triages these findings. By weighing the rarity of the source IP against the presence of sabotage-related query strings, the hunt determines a verdict. If the triage confirms unauthorized account renaming or parameter modification, the workflow directs immediate isolation of the impacted controller.

### What This Hunt Cannot See

This hunt relies on HTTP metadata. If attackers communicate with the xml.cgi endpoint over HTTPS and the network sensor does not perform TLS inspection, the URL paths and query strings remain invisible. In such cases, the hunt only sees the connection event, not the exploit intent.

Additionally, this design examines URL components. If the adversary sends commands within the HTTP POST body rather than via GET query strings, this hunt will miss the specific parameters being modified. Organizations should ensure their sensors capture POST bodies for high-risk CGI paths to mitigate this risk.

### How to Run It

This hunt is available as an open `hunt.md` playbook. You can import it into Huntbase or any `hunt.md`-aware runtime. The playbook includes parameters for lookback windows and known malicious IPs, allowing you to customize the search based on your specific threat intelligence and environment retention policies.
