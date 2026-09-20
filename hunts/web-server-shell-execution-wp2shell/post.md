# Hunting wp2shell RCE and Post-Exploitation on WordPress Servers

### The wp2shell Exploit Chain

Elastic Security Labs recently published an analysis of wp2shell (https://www.elastic.co/security-labs/blog/wp2shell-wordpress-rce-detection-elastic-defend), a pre-authentication RCE chain that targets WordPress environments. This specific exploit involves the staging of a malicious plugin and the execution of commands via the web server process. Because web servers frequently perform routine maintenance or run legitimate scripts, a standard detection rule for shell execution often creates too much noise for a security operations center. This hunt provides a structured way to verify these leads by looking for the behavioral markers that follow a successful exploit.

### Hypothesis

An adversary exploits a WordPress vulnerability to spawn a shell from a web server process. They then perform system discovery to understand the environment and eventually clean up the wp2shell plugin files to hide their traces.

### How the Hunt Flows

The hunt starts at the host process surface. The first phase queries process activity to find instances where a web server parent, such as Apache, Nginx, or a PHP-FPM worker, spawns a command shell like bash or sh. This transition is the primary indicator of remote command execution. The query focuses on identifying the user context and the working directory to establish an initial lead.

Once the hunt identifies a suspicious shell spawn, the analyst evaluates the results. If the shell runs as a low-privileged user (like www-data) or executes from a web root, the hunt moves into a corroboration phase. This pivot is critical: we do not want to run expensive behavioral searches against every host until we have a reason to believe an intrusion occurred.

In the final phase, the hunt fans out across two surfaces in parallel. On the process surface, it searches for rare reconnaissance commands. The adversary often runs commands like id, uname, or searches for SUID binaries immediately after gaining access. The hunt baselines these commands across the fleet, highlighting actions that only occur on a small number of hosts. Simultaneously, on the file surface, the hunt looks for the deletion of files in the wp-content/plugins or wp-content/uploads directories. The wp2shell exploit typically cleans up its own staging zip files and plugin directories once it establishes a foothold.

### Why This Is a Hunt, Not a Detection

A simple detection rule often triggers on any shell spawned by a web server, which can lead to high false-positive rates in environments with complex administration scripts. We treat this as a hunt because it requires correlating the initial lead with behavioral context and state changes, such as file deletions. By weighing the shell spawn against rare commands and cleanup actions, an analyst can confirm an actual intrusion with much higher confidence than a standalone alert.

### Blind Spots

The hunt relies on detailed process telemetry. If the logging system does not capture the parent command line, it becomes difficult to distinguish between a legitimate server restart and an exploit-driven shell spawn. Additionally, the cleanup detection requires file activity logging that specifically tracks deletions (activity_id 4) in the web root. If these logs are suppressed to save volume, the post-exploitation phase remains invisible.

### How to Run This Hunt

This playbook is available as a hunt.md file. You can import it into Huntbase or any runtime that supports the hunt.md standard. The playbook includes the gated logic to ensure you only perform deep investigation on hosts that show the initial RCE indicators.
