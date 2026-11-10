# Hunting for Gorbag APT Rapid Harvester Deployment

### Why now

ESET Research recently published Gorbag: Orcs at the border harvesting intelligence from Ukraine (https://www.welivesecurity.com/en/eset-research/gorbag-orcs-border-harvesting-intelligence-ukraine/), detailing a campaign targeting Ukrainian strategic entities. The actor, likely aligned with Russian interests, uses spearphishing lures and a WinRAR path traversal vulnerability to deploy ephemeral tools. These tools steal browser data and establish remote access, often removing themselves shortly after execution. We developed this hunt to find these transient artifacts before they disappear.

### The Hypothesis

An intruder deploys the Gorbag compromise chain by exploiting a WinRAR vulnerability or using macro-enabled lures to drop transient harvesters into ProgramData and establish startup folder persistence.

### How the hunt flows

The hunt begins by scoping the environment for hosts vulnerable to CVE-2025-8088. Identifying endpoints with vulnerable versions of WinRAR allows an analyst to prioritize behavioral checks on the most likely targets of the path traversal exploit.

The delivery phase uses two parallel queries to find initial evidence. The first query looks for specific lure filenames identified in the Gorbag campaign, such as taxation-related spreadsheets or archive files. The second query identifies rare file drops where Microsoft Excel or WinRAR create files in the ProgramData directory. This focuses on the behavioral pattern of the dropper rather than just static filenames.

If the delivery phase identifies suspicious hosts, the hunt pivots to persistence. An analyst looks for the creation of LNK files in the Windows Startup folder. The adversary uses these shortcuts to ensure their harvesters or reverse shells persist across reboots, often pointing back to the payloads staged in ProgramData.

The final enrichment step examines PowerShell script block logs for the Prime loader. The query searches for scripts that combine base64 decoding with references to the ProgramData path. This pattern corroborates the in-memory execution of the final payload and links the initial file drop to active execution.

### Blind spots

This hunt has two primary blind spots. First, if PowerShell script block logging (Event ID 4104) is not enabled, the execution logic of the Prime loader remains invisible. The analyst must then rely entirely on file creation and persistence events. Second, Gorbag tools are designed for rapid execution and self-deletion. If the harvester has already completed its task and wiped its own files, the hunt relies on historical logs or USN journal artifacts which may be rotated or overwritten.

### How to run it

This hunt is available as an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your fleet. It provides a structured flow to move from vulnerability context to behavioral triage and containment.
