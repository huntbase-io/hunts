# Hunting Sideloaded AppX Packages for OAuth Token Theft

### Why this hunt?
Recent research from Huntress (OAuth Token Theft Through Microsoft's Front Door, https://www.huntress.com/blog/stealing-oauth-tokens-through-microsofts-front-door) describes a technique where adversaries use sideloaded AppX packages to harvest OAuth tokens. By abusing the Windows Web Authentication Broker, an attacker can present a legitimate Microsoft login dialog that bypasses browser-based security and standard phishing blocks. This hunt identifies the specific endpoint signals that precede and accompany this activity.

### The Hypothesis
An adversary enables Developer Mode and sideloads a malicious AppX package to abuse WWAHost.exe. This allows them to capture MFA-compliant OAuth tokens via a legitimate Microsoft login dialog. Because the process is signed by Microsoft and the traffic goes to legitimate identity endpoints, this behavior often evades simple network-based blocks or reputation filters.

### How the Hunt Flows
The hunt begins with a scoping phase to identify where the prerequisite for sideloading exists. We query the registry for changes to the AppModelUnlock key, specifically looking for the AllowDevelopmentWithoutDevLicense value being set to 1. This setting is a requirement for installing any AppX package not sourced from the Microsoft Store, making it a critical indicator of environment preparation.

Next, the hunt runs two queries in parallel to find evidence of the actual attack. The first query examines process activity for the Add-AppxPackage command used with the -Register flag. To separate legitimate developer activity from an attack, we stack-count these commands across the estate. We focus on packages registered from local paths that appear on three or fewer hosts.

Simultaneously, the second query monitors the network activity of the Windows Web App Host (WWAHost.exe). This process acts as the proxy when a sideloaded application invokes the Web Authentication Broker. We look for outbound connections from WWAHost.exe to known Microsoft authentication domains such as login.microsoftonline.com or login.live.com.

Finally, an analyst or automated agent triages these results to provide a per-host verdict. The hunt looks for the specific correlation of a rare package registration followed by authentication traffic from WWAHost.exe on the same host. This link confirms that the sideloaded application is actively acting as a proxy for credential theft.

### Blind Spots
This hunt has two main limitations. First, if Developer Mode was enabled before the lookback window, the initial scoping query will not identify the configuration change. In these cases, the hunt relies entirely on the rarity of the registration command. Second, if endpoint telemetry for signed Microsoft binaries like WWAHost.exe is suppressed or filtered by your security stack, the network connections will be invisible, hiding the proxying behavior.

### How to Run It
This hunt is a hunt.md playbook. You can import it into Huntbase or any environment that supports the hunt.md format. It provides a structured way to investigate endpoint preparation and execution without the noise of a single-rule detection, which would likely fire on legitimate developer activity if not properly stack-counted and correlated.
