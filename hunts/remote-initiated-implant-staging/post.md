# Hunting for Node.js Implant Staging via Remote IT Support Abuse

## Why this hunt
The Microsoft Security blog recently detailed a campaign titled [Impersonating IT support: how threat actors turn a remote session into enterprise-wide access](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/). This activity involves attackers using Microsoft Teams to impersonate helpdesk personnel, eventually convincing users to share their screen via Quick Assist. This hunt focuses on the subsequent stage: where the attacker uses that access to stage an implant and gain a permanent foothold.

## Hypothesis
We hypothesize that an adversary is using interactive remote assistance sessions to socially engineer users into performing or allowing silent installations of malicious MSI packages. These packages deliver a portable Node.js runtime and an encrypted JavaScript implant to user-writable paths, bypassing standard installation directories to evade permissions-based security controls.

## Hunt Flow
The hunt begins by scoping the environment for hosts running Microsoft Teams or Quick Assist. This narrows the field to endpoints where the described social engineering vector is possible and focuses telemetry analysis on vulnerable workstations rather than servers or jump-boxes.

Next, we look for command shells or script interpreters spawned directly by these collaboration tools. Seeing `cmd.exe`, `powershell.exe`, or `wscript.exe` as a child process of `quickassist.exe` or `teams.exe` is a high-confidence indicator of hands-on-keyboard activity following a support session, which is highly anomalous for typical end-users.

We then search for silent MSI installations targeting user-writable paths like `AppData`. Using `msiexec.exe` with the `/qn` flag to target files like `devfix.msi` or `hotfix.msi` in a user profile is a signature move for this campaign. In a standard corporate environment, silent installs into user profiles are rare and typically indicate an attacker staging tools without administrative privileges.

The hunt also includes a baselining step for the Node.js runtime. We look for `node.exe` or processes with a Node.js file description running from `LocalAppData` or `Public` folders. We specifically look for instances that occur on a very small number of hosts, as legitimate Node-based applications are usually more prevalent across the fleet.

Finally, we corroborate these findings with DNS activity to official Node.js distribution domains and the creation of temporary binary or data files in user profiles. This helps confirm that the runtime was fetched and the payload was staged, providing the context needed for an incident response verdict.

## Blind Spots
There are two primary blind spots in this design. First, if EDR telemetry is incomplete for process command lines, the link between the remote session and the MSI download might be obscured. Second, without ingesting Teams-specific external access logs, we cannot identify the external tenant used by the attacker or the specific chat content used to lure the victim.

## How to run this hunt
This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any runtime aware of the `hunt.md` format. It is designed specifically as a hunt because silent MSI installs and remote tool usage occur legitimately in many environments; the value lies in the manual correlation of these events across different surfaces.
