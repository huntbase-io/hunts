# Hunting Tampered Exodus Wallet Installers and Modular RAT Persistence

### The Origin of the Hunt

Recent research by Huntress, titled [The Crypto Wallet That Never Opened: Tampered Exodus Installer Hides a Modular RAT](https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat), details a campaign where a modular RAT is delivered via a tampered installer for the Exodus crypto wallet. The attack leverages user-level permissions to stage an MSI that installs a persistent backdoor without requiring administrative rights or showing a user interface. This hunt is designed to find the breadcrumbs left by this infection chain across your environment.

### Hypothesis

We hypothesize that an intruder has deployed a tampered cryptocurrency wallet using a double-extension JS dropper or a ZIP-staged file. Following initial access, the actor uses a silent MSI installation from the user's temporary directory to establish persistence via a hidden scheduled task (INetHealth), which utilizes the `--headless` conhost wrapper to execute malicious PowerShell commands in the background.

### How the Hunt Flows

The hunt begins with fleet-wide scoping of software inventory. We look specifically for anomalous metadata, such as a package named "Background Service" authored by "Apple Inc"—a common indicator in this campaign—or the specific Exodus version (24.33.4) identified as the target for tampering.

Next, the hunt pivots to process activity to identify silent MSI executions. We specifically look for `msiexec.exe` calls that include `/quiet` or `/qn` flags and originate from user `TEMP` directories. This behavior is a strong indicator of the dropper's execution phase, where the malicious payload is silently unpacked and installed.

Persistence is then investigated by searching for the `INetHealth` scheduled task. Because the actor uses the `conhost --headless` flag to prevent a command window from appearing, we stack-count all instances of headless conhost usage across the environment. Rare or unique command lines in this context often reveal the encoded PowerShell commands used to maintain the backdoor.

Finally, we examine file activity for staging artifacts. This includes looking for the `.zip.###` folder pattern created by Windows Explorer when a user opens a file directly from a ZIP archive, as well as the presence of the `ExdBackupTool` directory in the user's AppData folder.

### Blind Spots

This hunt relies on comprehensive endpoint telemetry. If hosts are not enrolled in the telemetry provider or if the logs do not capture parent-child process relationships, the context for the initial infection may be lost. Furthermore, while we can see the execution of the MSI, we may lack visibility into the specific logic of the initial JavaScript dropper if script content capture is not enabled. Lastly, if the actor reparents processes to `explorer.exe` effectively, standard process tree detections might be bypassed, requiring a heavier reliance on the file and task artifacts.

### How to Run This Hunt

This hunt is packaged as a `hunt.md` playbook. It can be imported into Huntbase or any other `hunt.md`-aware runtime. It is designed to be a point-in-time sweep of your environment to identify infected hosts and facilitate rapid isolation and forensic collection.
