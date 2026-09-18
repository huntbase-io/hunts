# Hunting iClickFix WordPress Compromise and TDS Redirection Patterns

### Why now
Recent research by Sekoia [Meet iClickFix: A widespread WordPress-targeting framework](https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/) highlights a sophisticated distribution framework that compromises WordPress sites to serve ClickFix social engineering lures. Unlike traditional phishing, this framework turns trusted internal or public-facing WordPress servers into watering holes, making it harder to distinguish malicious traffic from legitimate web activity. We have published this hunt to help teams identify if their own WordPress infrastructure is being used as a staging ground or if users are interacting with these redirection chains.

### The Hypothesis
Our hypothesis is that internal WordPress servers have been compromised to host tracking scripts that act as the entry point for iClickFix. These scripts collect visitor telemetry and use a Traffic Distribution System (TDS) based on YOURLS to redirect qualified victims to a ClickFix social engineering lure, eventually leading to a NetSupport RAT payload.

### How the hunt flows
The hunt begins with a scoping phase to identify all WordPress instances within the estate using software inventory data. These hosts are treated as the primary surfaces for potential compromise. By narrowing our focus to these servers, we can more effectively monitor for the outbound DNS and HTTP signals associated with the iClickFix infrastructure without being overwhelmed by general web traffic.

Next, the hunt analyzes DNS telemetry to find connections to known-malicious redirection domains. We specifically look for resolutions from the identified WordPress servers to domains used for script delivery or C2. If these resolutions are found on non-server endpoints, it may indicate a user has already triggered the redirection chain from an external site.

We then correlate this with HTTP activity, looking for specific URI patterns used by the YOURLS-based TDS, such as /gigi, /ofofo.js, and /liner.php. A critical step in this hunt is the use of baselining to find rare instances of fingerprint exfiltration. The iClickFix framework transmits JSON-like data (containing host and timing information) via URL query parameters. By stacking these occurrences and filtering for rare destinations, we can uncover rotated or previously unreported infrastructure.

Finally, the hunt triages the entire redirection chain. We look for the sequence of a WordPress site referral, a TDS path hit, and the subsequent exfiltration of browser data to determine if a successful redirection occurred. This allows for the isolation of the host before the user follows the social engineering instructions to execute the final payload.

### Blind spots and limitations
This hunt has two primary blind spots. First, without TLS/SSL decryption, the specific URL paths (like /gigi) will not be visible in network traffic, forcing the hunt to rely on DNS resolution and destination IP stacking. Second, since most endpoint telemetry does not include the HTTP response body, we cannot directly observe the 'ic-tracker-js' script injection on the WordPress page; we can only infer its presence based on the resulting outbound traffic.

### How to run it
This hunt is provided as a `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime that supports the open hunt.md format. Once imported, you will need to provide your internal WordPress hostnames or allow the first scoping step to populate them for you.
