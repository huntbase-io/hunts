# Hunting UAT-12643 Stager Abuse and Registry Persistence

### Why now

Cisco Talos recently published a report on [UAT-12643](https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/), a suspected North Korea-aligned actor targeting blockchain users. The adversary uses signed binaries and masquerading to bypass standard security controls, focusing their efforts on users of specific VoIP and messaging applications.

### The hypothesis

The adversary stages payloads using signed Windows binaries on hosts running specific messaging or VoIP software. They then establish persistence through masqueraded binaries in user-writable paths, such as fake Edge updaters or runtime brokers, ensuring they survive reboots without requiring administrative privileges.

### How the hunt flows

The first phase filters the fleet for hosts running targeted software like Viber or MicroSIP. This scoping concentrates the hunt on the actor's preferred entry points and reduces the volume of data processed in later stages.

Next, the hunt queries for LOLBin abuse. It identifies processes like certutil, MpCmdRun, mshta, or MSBuild performing remote downloads or executing scripts. These signed binaries often evade basic execution blocks, but their command-line arguments reveal suspicious staging behavior.

If the lead query finds suspicious activity, the hunt pivots to registry and file activity. It searches for the MsgEdgeUpdate run key and identifies rare binaries in AppData or Temp folders. This correlates the initial staging behavior with the establishment of long-term presence on the endpoint.

Finally, an analyst or automated agent synthesizes the results. They confirm if the rare binaries match the actor's known masquerading patterns and determine if the full stager-to-persistence chain exists on the host.

### What this hunt cannot see

This hunt relies on command-line and registry telemetry. If an environment lacks argument logging for MpCmdRun or registry write events, the stager and persistence steps cannot confirm the threat. The hunt also misses activity if the adversary uses MSBuild to compile and execute code entirely in memory without writing files to disk.

### How to run it

This hunt is an open hunt.md playbook. You can import it into any hunt.md-aware runtime or the Huntbase platform to execute the queries and automated analysis steps. Because it uses a gated flow, you can run the initial scoping and lead queries without generating the volume of alerts typical of broad LOLBin monitoring.
