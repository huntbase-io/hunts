# Gamaredon GammaLoad Persistence and Registry C2 Configuration Hunt

### Why this hunt

Gamaredon, also known as UAC-0010, continues to use GammaLoad for initial staging and persistence. Recent analysis from Sekoia.io in their report FSB Matryoshka: Gamaredon GammaLoad (https://blog.sekoia.io/fsbs-matryoshka-2-3-gamaredons-gifts-that-keeps-unpacking-gammaload/) details how the loader manages its C2 configuration.

### Hypothesis

An intruder has established persistent access using GammaLoad VBScripts. These scripts manage C2 configuration via registry keys in HKCU\Console and execute via a high-frequency task invoking an Alternate Data Stream.

### How the hunt flows

The hunt begins by scoping active Windows hosts. This limits the broad queries to systems where the GammaLoad VBScript and its registry-based configuration mechanisms operate.

The next phase fans out to three surfaces simultaneously. The registry query searches for URL or IP address strings stored within HKCU\Console. This is a primary indicator of GammaLoad's failover logic, where the script caches active C2 addresses to avoid repeated discovery lookups.

The persistence query looks for the 11-minute scheduled task. It specifically flags tasks that invoke script interpreters like cscript or wscript against files in the Temp directory, or those that explicitly use the colon syntax for Alternate Data Streams.

The network query identifies DNS requests to known Dead Drop Resolvers (DDR). Legitimate services like Telegraph, Telegram, and Check-Host are used to host the current C2 address. Seeing these resolutions on a host that also shows the specific registry or task behavior confirms the infection.

An analyst triages these results. By linking the registry values, task command lines, and network activity, the hunt produces a high-confidence verdict for each host.

### Blind Spots

This hunt relies on endpoint registry and task telemetry. If a host does not report registry changes, the persistent configuration remains hidden. Additionally, some telemetry providers may truncate or fail to log the colon character in file paths, which hides the use of Alternate Data Streams in scheduled tasks.

### How to run it

This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your fleet. It provides a structured way to investigate Gamaredon activity beyond simple file-based detections.
