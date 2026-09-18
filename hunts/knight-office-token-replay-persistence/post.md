# Hunting Knight Office M365 Token Replay and Rogue Identity Persistence

Adversary-in-the-Middle (AiTM) attacks continue to evolve, moving beyond simple credential harvesting to sophisticated session theft. A recent analysis by Huntress titled [Inside Knight Office, a New M365 AiTM Phishing Kit](https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack) details how this specific kit facilitates the theft of session tokens and subsequent persistence. Once a session is stolen, the adversary is no longer hindered by MFA, allowing them to perform administrative actions or register new devices to maintain long-term access.

### The Hypothesis
We hypothesize that an adversary is replaying these stolen session tokens to authenticate against the Microsoft Authentication Broker. Their primary objective is likely establishing persistence by registering rogue Windows Hello for Business (WHfB) keys or enrolling new devices into the Entra ID tenant. Because the session token is already 'MFA-satisfied,' these actions often occur without triggering additional security prompts.

### How the Hunt Flows
The hunt begins by narrowing the scope to assets known to run Microsoft 365 or Office software. By filtering the software inventory, we reduce the noise in endpoint telemetry, focusing our efforts on the most likely targets for session theft.

In the detection phase, we examine authentication logs for successful sign-ins to the Microsoft Authentication Broker. We specifically look for events where MFA was not satisfied or where the source IP matches known Knight Office infrastructure. This is a critical pivot; a successful login to the Broker without a fresh MFA challenge suggests a replayed session token.

We then correlate these cloud-plane anomalies with endpoint HTTP activity. The Knight Office kit and associated automation often use specific User-Agents like `python-requests` or `Dsreg`. We baseline these agents across the fleet to find rare instances that deviate from standard user behavior. The presence of `Dsreg` traffic is particularly concerning as it is associated with device registration and key enrollment.

Finally, we look for successful cloud sign-ins to sensitive endpoints such as `OfficeHome` or `dsreg` (device registration) that occur in the same timeframe as the rare User-Agent activity. This cross-surface correlation allows an analyst or agent to determine if a specific identity has been compromised and whether the adversary has successfully established a persistent foothold.

### Blind Spots and Limitations
This hunt relies heavily on the correlation between endpoint HTTP telemetry and cloud authentication logs. If the adversary uses a different IP address for replaying the token than they did for the initial theft (e.g., via rotating residential proxies), the link between the endpoint activity and the cloud login may be obscured. Furthermore, standard Entra ID logs often lack User-Agent strings, requiring defenders to pivot back to endpoint data to see the scripted agents used by the kit.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. This format is designed for portability and can be imported directly into Huntbase or any security orchestration platform that supports the `hunt.md` standard. Because this is a hunt and not a static detection, it requires the analyst to review the timing and context of the alerts to distinguish between legitimate administrative enrollment and adversary persistence.
