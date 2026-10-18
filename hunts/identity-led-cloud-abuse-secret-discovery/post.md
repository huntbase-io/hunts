# Hunting Identity-Led Cloud Abuse and Secret Discovery

### Why this hunt matters
In a recent post, Sekoia Digital Risk (https://www.sekoia.com/blog/with-sekoia-intelligence-we-gave-you-half-the-picture-heres-the-other-half) highlights the shift toward identity-led breaches. Attackers no longer rely solely on exploits; they use stolen credentials to walk through the front door. This hunt focuses on the 'other half' of that picture: what happens after a credential is stolen. We focus on the transition from an unmanaged device sign-in to the discovery of high-value secrets.

### Hypothesis
An attacker uses stolen credentials harvested from unmanaged devices to bypass MFA via push fatigue, subsequently discovering cloud secrets and internal shares to exfiltrate data.

### How the hunt flows
The first phase scopes the environment for risk. The query identifies users signing in from non-compliant or unmanaged devices using the `hb_auth_signin` surface. These sign-ins represent the highest risk for credential theft, as personal devices often lack the endpoint protections found on corporate assets.

Next, the hunt pivots to authentication patterns. It looks for MFA push fatigue, specifically targeting instances where multiple authentication failures are followed by a single success. We enrich this data using Hudson Rock domain exposure logs to see if the organization’s credentials are currently circulating in stealer markets.

Once a suspicious identity is identified, the hunt fans out to look for resource discovery. It examines the `hb_cloud_api_activity` surface for sensitive operations like `GetSecretValue` or `AssumeRole`. Simultaneously, it checks `hb_smb_activity` for access to administrative shares or backup folders. This correlation separates a simple login anomaly from a confirmed intrusion.

Finally, an agent evaluates the combined evidence. If the hunt connects a non-compliant sign-in and MFA fatigue to specific secret discovery, it triggers a recommendation for account suspension.

### Blind spots
This hunt has two primary limitations. First, it requires visibility into device compliance; if the identity provider does not track device state, we cannot distinguish between managed and personal hardware. Second, it does not detect session cookie replay. If an attacker steals a valid session token, they bypass the authentication logs entirely, making their activity appear as a continuation of a valid session.

### How to run it
This hunt is provided as a `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the open hunt.md standard. The playbook includes the necessary queries for authentication and cloud API surfaces, alongside logic to correlate findings across identity and resource providers.
