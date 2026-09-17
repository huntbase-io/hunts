# Hunting TerminalFix Python Reverse Tunnels and Domain Discovery

### Why Now

Recent research from Microsoft, [TerminalFix campaign deploys a reverse tunnel through multistage intrusion](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/), details a complex intrusion chain involving social engineering and steganography. This hunt focuses specifically on the final objectives: establishing a persistent reverse tunnel and conducting Active Directory reconnaissance. 

### The Hypothesis

We hypothesize that an adversary is utilizing a windowless Python interpreter (`pythonw.exe`) to establish an encrypted WebSocket channel to attacker-controlled infrastructure. Once this tunnel is established, the adversary performs automated discovery of domain trusts and administrative groups, often pivoting from a legitimate-looking process like `LockScreenContentServer.exe` to avoid immediate detection by traditional process monitors.

### How the Hunt Flows

The hunt begins by scoping the environment for the specific execution of windowless Python interpreters or the `LockScreenContentServer.exe` binary. This step is critical because these processes serve as the execution host for the reverse tunnel. We look for these in user-writable directories or under unusual parent-child process relationships that deviate from standard system behavior.

Once potential hosts are identified, the hunt pivots into parallel telemetry analysis. The first branch looks for reconnaissance activity, specifically the execution of tools like `nltest.exe`, `net.exe`, or `ping.exe` with arguments targeting domain controllers, SQL servers, or gateways. We use frequency analysis to identify bursts of activity that differ from routine administrative work.

The second branch examines network telemetry, looking for DNS resolutions of the campaign's C2 infrastructure (specifically `gitnow.dev`) and established outbound connections on port 443. We are looking for long-lived sockets originating from the Python interpreter, which are indicative of a persistent reverse tunnel rather than a standard web request.

The final phase involves a triage agent that correlates these signals. We are looking for the convergence of a windowless Python process, active reconnaissance commands, and an established network tunnel on a single host. This correlation is what differentiates this hunt from a simple detection rule, as it reduces false positives by verifying the behavioral chain of the campaign.

### Blind Spots

This hunt relies on endpoint visibility. Unmanaged hosts in the network serving as a pivot for the tunnel will remain invisible to this playbook. Furthermore, while we can identify the existence of the WebSocket tunnel, the content within the encrypted channel remains opaque without TLS inspection. We can see the tunnel exists, but we cannot see the specific commands passing through it.

### How to Run This Hunt

This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any other `hunt.md`-aware runtime. Because it utilizes behavioral stacking and multi-surface correlation, it is best run on domain-joined Windows endpoints where administrative activity is expected but can be baselined. TerminalFix campaign deploys a reverse tunnel through multistage intrusion.
