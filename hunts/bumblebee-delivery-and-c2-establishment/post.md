# Hunting Bumblebee Delivery via SEO Poisoning and AdaptixC2 Side-Loading

### Why this hunt

The DFIR Report recently detailed a campaign where Bing search results led directly to Akira ransomware in their article, [From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira](https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/). The intrusion begins with a trojanized ManageEngine installer delivered via SEO poisoning. This hunt focuses on identifying the early stages of this infection: the initial web redirection and the side-loading execution on the endpoint.

### Hypothesis

An intruder lures an administrator to a look-alike download page via SEO poisoning, leading to a trojanized installer that side-loads Bumblebee via consent.exe and establishes AdaptixC2.

### How the hunt flows

The first step in this hunt is identifying the entry point. The hunt searches DNS telemetry for resolutions to domains known to host the malicious redirection infrastructure. The adversary uses domains like opmanager.pro and download-center.online to trick users who are searching for legitimate administrative software. By starting with these high-fidelity leads, the hunt narrows the scope of the investigation from the entire fleet to only those hosts that have interacted with the reported delivery mechanism.

Once the hunt confirms a DNS lead, it pivots to endpoint process activity. It looks for instances of the legitimate Windows binary consent.exe executing from user-writable directories. In the Bumblebee campaign, the adversary side-loads their loader by placing a malicious DLL alongside this system binary in folders within the AppData or Temp paths. Seeing a system binary like consent.exe run from anywhere other than C:\Windows\System32 is a strong indicator of this side-loading technique.

In parallel, the hunt performs frequency analysis on all binaries running from these same user-writable paths. By stacking these processes across the environment, the hunt highlights rare binaries that may be unique to the infection. This captures the dropped Bumblebee loader or the renamed Address Book utility, often seen as AdgNsy.exe, which the adversary uses for shellcode injection.

The final phase correlates these execution leads with network telemetry. It looks for outbound connections to known AdaptixC2 infrastructure or traffic originating from the suspicious processes identified in the previous steps. This multi-surface pivot provides the context necessary to distinguish a standard software installation from an active intrusion.

### What the hunt cannot see

Visibility relies heavily on telemetry retention and path-aware auditing. If DNS logs do not cover the initial redirection window, the hunt misses the entry point. If process monitoring does not capture the full execution path for system binaries, the side-loading of consent.exe from AppData appears as a legitimate system process. The hunt also cannot see the initial search query on the search engine, only the resulting domain resolution.

### How to run it

This hunt is a hunt.md playbook. It is a portable, machine-readable format that you can import into Huntbase or any runtime that supports the hunt.md specification. The playbook includes the specific DNS domains and C2 IP addresses identified in the campaign to help you quickly scope your environment and triage the findings.
