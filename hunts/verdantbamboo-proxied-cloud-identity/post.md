# Hunting for VerdantBamboo Proxied Authentications to M365

Volexity recently published an analysis titled [VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall](https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/), detailing how the WARP PANDA group compromises unmanaged appliances to facilitate further operations. One of the more persistent challenges highlighted is their use of these devices as internal proxies. By routing authentication traffic through an appliance located inside the corporate network, the adversary can make their M365 access appear as if it is coming from a trusted egress point, effectively neutralizing many IP-based conditional access policies.

### The Hypothesis

Our hunt is built on the hypothesis that an adversary has already compromised an internal appliance (such as a storage sync server, a firewall, or a NAS) and is using it to authenticate to M365. The goal is to detect sessions that originate from your trusted corporate egress IPs but exhibit behaviors inconsistent with legitimate on-site usage, specifically focusing on the lack of Multi-Factor Authentication (MFA) or the use of legacy protocols that bypass modern controls.

### How the Hunt Flows

The hunt begins at the device inventory level, using the `hb_devices` surface. We search for hostnames and device profiles that match unmanaged or high-value targets like Egnyte, Synology, or pfSense. This scoping step is necessary because these devices are rarely monitored by EDR, making them ideal candidates for the BRICKSTORM or PLENET backdoors described by Volexity.

Next, we pivot to the identity plane via `hb_auth_signin`. We look specifically for successful M365 logins originating from known corporate egress IPs. We filter these results for sessions where MFA was not satisfied or where the authentication protocol falls outside of modern standards (SAML/OAuth2). This highlights 'trusted' logins that are actually high-risk.

To separate legitimate admin activity from malicious proxying, we perform a parallel correlation. We baseline user-to-IP relationships to find identities appearing on a corporate egress IP they do not typically use. Simultaneously, we examine `hb_network_connection` logs from our scoped appliances. We are looking for outbound HTTPS traffic from these appliances to M365 or Azure IP ranges—traffic that is often atypical for a storage or network device's primary function.

The final stage involves a triage process where we align the timestamps of the anomalous logins with the outbound traffic from the candidate appliances. If a rare user login from an egress IP matches an appliance's outbound connection to a Microsoft endpoint, the probability of a proxied session is high.

### Blind Spots and Limitations

This hunt has two primary limitations. First, it relies heavily on the accuracy of MFA reporting in your identity logs. If your log source cannot definitively distinguish between 'MFA not required' and 'MFA bypassed,' you may encounter false negatives. Second, we lack direct visibility into the processes running on the appliances themselves. Because these devices often cannot run EDR, we are inferring the proxying behavior from network and identity metadata rather than observing the malicious binary directly.

### How to Run This Hunt

This hunt is packaged as an open `hunt.md` playbook. It can be imported directly into Huntbase or any other hunt-aware runtime. Because this is a hunt, not a static detection, it is designed to be run iteratively as you refine your list of corporate egress IPs and appliance keywords. You can find the full playbook in our repository.

VerdantBamboo's tactics succeed because they exploit the trust we place in our own network perimeter. A negative result in this hunt is valuable—it confirms that your edge trust model is currently holding and that stolen credentials are not being funneled through your own hardware.
