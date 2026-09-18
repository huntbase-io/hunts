# Hunting TeamPCP Activity in AWS ECS Environments via SSM Agent

Recent research by Wiz, titled [Tracking TeamPCP: post-compromise attacks seen in the wild](https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild), details a threat actor specializing in leveraging stolen cloud credentials to gain a foothold in containerized environments. Once inside, TeamPCP often pivots from static credentials to interactive runtime control using the AWS Systems Manager (SSM) Agent, a feature known as ECS Exec. We have designed this hunt to identify these interactive sessions and the subsequent discovery activity.

### The Hypothesis
An adversary who has obtained cloud credentials will utilize the legitimate AWS SSM Agent to spawn interactive shells (bash, sh) or Python interpreters directly inside running ECS containers. This allows them to bypass traditional network entry points and perform discovery, such as listing secrets or describing cloud infrastructure, from a trusted compute environment. 

### How the Hunt Flows
The hunt begins by establishing a scope using the `hb_software_inventory` surface. We identify all container hosts where the `amazon-ssm-agent` or `ssm-agent-worker` is present. This narrows our search to only those assets capable of supporting ECS Exec, reducing the noise from standard container workloads that do not use these management features.

Next, we pivot to `hb_process_activity` to find child processes spawned by these agents. We specifically look for shells and Python interpreters. While ECS Exec is a common tool for developers, an interactive session triggered by an adversary often leaves distinct traces in the process tree that differ from automated management scripts or health checks.

To separate legitimate activity from the "bold" manual sessions typical of TeamPCP, we perform a prevalence check on the command lines. By baselining the entire fleet, we isolate commands that appear on only one or two hosts. This highlights manual, one-off execution that deviates from standard DevOps workflows, such as the specific script names reported in recent attacks.

Finally, we enrich the findings using `hb_script_activity`. We search for script blocks containing AWS-specific reconnaissance patterns, such as `get-caller-identity`, `list-secrets`, or the use of the `boto3` library. This allows us to see the intent behind the session, confirming if the SSM-spawned shell was used to interrogate the cloud environment.

### Blind Spots and Limitations
This hunt has two primary limitations. First, if Linux script logging (via Auditd or eBPF) is not enabled, the `hb_script_activity` surface will be empty. In such cases, we must rely entirely on command-line arguments, which can be easily obfuscated or truncated. Second, while we can see what happened inside the container, endpoint logs do not reveal which external IAM identity initiated the session. Correlating these results with AWS CloudTrail `ExecuteCommand` events is necessary to identify the source of the compromise.

### Why This is a Hunt
A simple detection rule might flag any instance of the SSM Agent spawning a shell, but in many environments, this creates too much fatigue for SOC analysts. This is a hunt because it uses fleet-wide baselining to find outliers and correlates process behavior with actual script content. It is designed to find the human-in-the-loop activity that automated tools often overlook.

### How to Run it
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime that supports the `hunt.md` format. The playbook includes the necessary logic to perform the scoping, baselining, and triage steps automatically.
