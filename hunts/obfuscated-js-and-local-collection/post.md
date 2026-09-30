# Hunting for Obfuscated JavaScript and Malicious npm Scripts

### Why this hunt?
Talos Intelligence recently detailed how attackers use JavaScript obfuscation to transform simple phishing kits into persistent credential stealers in their article, [JavaScript obfuscation: From party trick to phishing kit](https://blog.talosintelligence.com/javascript-obfuscation-from-party-trick-to-phishing-kit/). While obfuscation is common in legitimate web development, its application within npm install scripts or browser extensions provides a stealthy path for local collection that traditional static analysis often misses.

### Hypothesis
An intruder uses obfuscated JavaScript within npm install scripts or malicious browser extensions to collect credentials and cookies from the local endpoint while evading static analysis.

### The Hunt Flow
The hunt begins by narrowing the search to hosts with npm or Node.js installed. This scoping step reduces noise by focusing on environments where developers frequently run packages that might contain malicious install hooks, rather than scanning the entire estate for general web traffic.

Once the scope is set, the hunt runs two parallel queries. The first identifies shell processes launched directly by npm or Node, which often indicates an install-time script execution. The second query scans script content for deobfuscation primitives like "atob", "String.fromCharCode", and "eval". These primitives are the building blocks of multi-stage script execution used to hide malicious intent.

An analyst then triages these findings. They look for instances where suspicious npm process chains correlate with the presence of deobfuscated script fragments. This stage filters out standard minified libraries that use similar functions for benign reasons by looking for non-standard parent-child process relationships.

The hunt then pivots to follow-on activity. It searches for rare browser extension file changes, specifically looking for new manifest files in user profile directories. This identifies persistence mechanisms that an obfuscated script might have installed to maintain access to the user's browser environment.

Finally, the hunt checks for the execution of collection utilities like "clip.exe" or "pbpaste". The use of these tools on a host that previously showed suspicious script behavior completes the attack chain, providing high-confidence evidence of an active intrusion focused on data theft.

### Blind Spots
This hunt relies on visibility into script block execution. If the telemetry does not capture the cleartext string at the final execution sink, the analyst only sees the obfuscated wrapper. Additionally, if an adversary uses an ephemeral extension—one that installs, steals data, and immediately uninstalls—the hunt may miss the persistence phase if it depends on snapshot-based inventory instead of real-time file event auditing.

### How to run this hunt
We provide this hunt as an open hunt.md playbook. This format allows you to import the logic into Huntbase or any other hunt.md-aware runtime. Because it is a hunt rather than a static detection, it allows for the manual review of script fragments and the flexibility to tune the baseline for rare extensions in your specific environment.
