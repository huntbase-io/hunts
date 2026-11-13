# Hunt for ClickFix Persistence via Sideloading and Reverse Tunnels

### Why this hunt

The Huntress team recently detailed the progression of ClickFix campaigns in their article, "The evolving tradecraft of ClickFix" (https://www.huntress.com/blog/the-evolving-tradecraft-of-clickfix). While early stages of these attacks rely on social engineering and clipboard manipulation, the endgame involves durable persistence. Adversaries now deploy batch scripts to stage DLL sideloading implants and maintain access through reverse SSH tunnels. This hunt finds these persistent footholds by looking for specific registry artifacts and behavioral anomalies.

### The Hypothesis

An attacker establishes persistence using ClickFix-dropped batch scripts that install DLL sideloading implants and reverse SSH tunnels to maintain long-term access. These scripts typically land in subdirectories of ProgramData, using random or campaign-specific names to evade notice.

### Hunt Flow

The hunt begins by inspecting registry activity to identify new or modified Run keys. The query specifically targets keys that point to the ProgramData directory or use campaign-specific value names like CertEnrollCtrl_Y0db6oZq9, LockScreenContentServer_qQrRrJiHX, or DuskDesk. Staging in ProgramData allows the adversary to maintain persistence across reboots while staying hidden in a directory often overlooked by casual inspection.

Next, the hunt pivots into a parallel investigation of module loads and network connections. The module query performs a stack-count on DLLs loaded from ProgramData subdirectories. It looks for rare modules—those appearing on three or fewer hosts—to identify potential sideloading. When an adversary sideloads a DLL, they often place it in a unique folder alongside a legitimate executable. By identifying these outliers across the fleet, we can isolate implants that use unique file names for every victim.

Simultaneously, the network query checks for connections to known reverse-tunnel infrastructure and C2 IPs. This step focuses on connections originating from processes frequently used to bridge network traffic, such as node.exe or powershell.exe. The presence of a connection to a known tunnel IP, combined with an unusual parent process, strongly suggests an active reverse shell or proxy.

An automated agent then triages these findings. It evaluates whether the registry persistence, rare module loads, and network activity occur on the same host. The agent assigns a verdict of malicious, suspicious, or benign based on the intersection of these behaviors. This correlation reduces the noise inherent in registry-only detections and ensures analysts focus on hosts where the full lifecycle of the implant is visible.

### Blind Spots

This hunt relies on endpoint visibility via registry and module load telemetry. If a host lacks an agent or EDR coverage, the persistence artifacts remain invisible even if the host participates in a reverse tunnel. Furthermore, if PowerShell Script Block Logging is disabled, analysts cannot inspect the contents of ephemeral scripts like r.ps1 used to establish the tunnel.

### How to Run This Hunt

This hunt is packaged as an open hunt.md playbook. You can import it directly into Huntbase or any runtime that supports the hunt.md format. Since this hunt is designed for periodic execution, you should run it across your fleet every 14 days to catch new implants as adversary infrastructure and naming conventions rotate.
