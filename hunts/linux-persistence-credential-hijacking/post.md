# Hunting for Linux Web Shells and Configuration Tampering

### Why this hunt
Unit 42 recently published AI-Powered Espionage Campaign Targets Government Linux Infrastructure (https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/). The report details how the CL-UNK-1211 actor uses AI-assisted code to create unique PHP web shells and modify Linux system profiles. These automated techniques allow the adversary to maintain stealthy foothills on government infrastructure. This hunt provides a structured way to find these artifacts.

### Hypothesis
The adversary establishes persistence on Linux web servers using AI-generated PHP web shells and hijacks administrative credentials by tampering with shell profiles and configuration files.

### How the hunt flows
The hunt starts by scoping the environment. The first query searches the hb_software_inventory surface for Linux hosts running PHP, Plesk, Nginx, or Apache. This step identifies the systems most likely to host the adversary’s web-based persistence. The analyst uses these results to focus the following detection steps.

After scoping, the hunt executes two detection branches in parallel. The process activity branch monitors the hb_process_activity surface for web server process managers spawning interactive shells or interpreters like bash, sh, or python. This behavior often indicates an active web shell session where the adversary executes commands in the context of the web user or a privileged account.

The file activity branch examines the hb_file_activity surface for modifications to critical configuration paths. It targets PHP configuration directories and user .bashrc profiles. This step uses a prevalence baseline to surface modifications that occur on five or fewer hosts. It also looks for specific deceptive filenames mentioned in the source report, such as plesk_sys_driver.php or Solarwinds.StatusLog.txt.

An automated agent then correlates the findings from both branches. It compares the user context of anomalous process execution against the actors involved in file tampering. This pivot helps the analyst distinguish between legitimate administrative maintenance and an automated intrusion. If the agent finds rare file modifications alongside suspicious shell execution, it flags the host for isolation and forensic review.

### What this hunt cannot see
This hunt faces limitations against high-speed automation. If an adversary uses an AI-driven agent to deploy a web shell, execute commands, and delete the shell within seconds, process-only telemetry might miss the brief execution window. Additionally, the hunt depends on active logging for configuration directories. If the system does not record file activity for /etc/php/ or /opt/plesk/, the modification to the persistent state will not appear in the results.

### How to run it
This hunt exists as an open hunt.md playbook. You can import the playbook into Huntbase or any other hunt.md-aware runtime. The design allows you to refresh the host scope before running the deeper behavioral queries, ensuring you target the correct infrastructure.
