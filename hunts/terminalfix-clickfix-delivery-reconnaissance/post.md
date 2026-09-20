# TerminalFix Intrusion: Detecting Fake Cloudflare Lures and AD Discovery

Recent reporting from Microsoft, "TerminalFix campaign deploys a reverse tunnel through multistage intrusion", details a threat that starts with a social engineering lure and ends with a persistent reverse tunnel. The campaign uses ClickFix tactics where a user is tricked into pasting a command to solve a fake Cloudflare verification issue. This hunt focuses on the early and middle stages of this intrusion.

### The Hypothesis

An intruder has used a fake Cloudflare verification lure to trick a user into pasting a PowerShell command, facilitating local directory staging and automated domain discovery.

### How the Hunt Flows

The first step scopes the environment for specific directory activity. The adversary stages files in a unique ProgramData path. The query identifies hosts where processes run from this folder or establish the path. This provides a focused list of suspicious hosts for deeper investigation.

Next, the hunt splits into two parallel investigative paths. The first path looks for the delivery interaction. It searches script activity for contents matching the fake Cloudflare "not a robot" or "verification" lures. This confirms that a user actually executed the malicious paste.

The second parallel path monitors for automated Active Directory discovery. The intruder often runs a burst of commands like nltest /domain_trusts or net group "domain admins". The hunt baselines this activity to identify clusters of discovery that are rare across the fleet.

Finally, the hunt weighs the evidence. An analyst or automated logic correlates the staging directory, the script lure, and the discovery burst. If a host matches the full chain, the hunt directs the user to isolate the host immediately to prevent further movement.

### What the Hunt Cannot See

This hunt relies heavily on PowerShell Script Block Logging (Event ID 4104). If logging is disabled, the pasted command will not appear in telemetry. Additionally, the hunt assumes endpoint visibility into registry and process activity. Unmanaged hosts or those not reporting these events remain hidden from the scoping steps. While the hunt identifies discovery activity, it does not see the encrypted traffic of the reverse tunnel itself if the initial staging is missed.

### How to Run the Hunt

This is a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. Because it uses a multi-stage approach, you should run the scoping query first to identify the primary targets before fanning out into the deeper script and discovery analysis.
