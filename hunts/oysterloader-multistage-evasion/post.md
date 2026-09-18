# Hunting OysterLoader Evasive Multi-Stage Infections

### Why hunt for OysterLoader?

Recent analysis by Sekoia in their report, [OysterLoader unmasked: the multi-stage evasion loader](https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/), details a sophisticated infection chain used by Rhysida ransomware affiliates. OysterLoader, also known as CleanUp or Broomstick, is designed to bypass traditional defenses through API hammering and custom LZMA decompression of its payload in memory. Because these techniques are specifically built to evade signature-based antivirus, a behavioral hunt is necessary to identify the loader during its staging phase.

### The Hypothesis

We hypothesize that an adversary is delivering trojanized MSI installers—often impersonating common utilities like PuTTY, WinSCP, or ChatGPT—to execute a multi-stage loader. This loader eventually executes shellcode in the memory space of a legitimate process. By identifying the initial lure and then pivoting to processes that lack a corresponding file on disk, we can surface active infections that have not yet reached the final ransomware deployment stage.

### How the Hunt Flows

The first phase focuses on scoping via the software inventory surface. We look for the installation of specific software lures or generic categories like 'AI' and 'Authenticator' tools delivered via MSI. While many of these installations are benign, they provide the necessary starting point for a high-fidelity pivot.

In the second phase, we examine process activity to find a high-fidelity indicator: processes running where the executable is no longer present on disk. We specifically look for these 'fileless' execution signatures occurring shortly after an MSI installation or a user-initiated launch from the shell. This targets the shellcode injection and unpacking stages of OysterLoader.

To reduce false positives from legitimate Just-In-Time (JIT) compilation or software updates, the third phase uses fleet-wide prevalence. We stack-count in-memory process executions across the environment, looking for rare instances that appear on only a handful of hosts. This is combined with a search for outbound HTTP traffic patterns—specifically GET requests to PHP endpoints or short, randomized paths—which match the known downloader check-in behavior.

### Blind Spots

This hunt relies heavily on EDR telemetry that can report the `on_disk` status of a running process. If your endpoint tooling does not provide visibility into whether a process is backed by a file, detecting the in-memory decompression stage will be significantly harder. Additionally, if the C2 communication is performed over TLS without inspection, the network-based check-in patterns may be invisible to the HTTP activity surface.

### How to Run This Hunt

This hunt is packaged as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime that supports the `hunt.md` format. The playbook contains the structured logic to guide an analyst through the scoping, detection, and corroboration phases, ending with a triage agent that provides a consolidated verdict for each host examined.
