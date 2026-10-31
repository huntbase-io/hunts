# Hunting AI-Scaled Social Engineering and Agentic Post-Exploitation

### Why this hunt

Microsoft recently highlighted a shift in North Korean tradecraft in their report, [Tracking AI adoption in North Korean threat actor tradecraft](https://www.microsoft.com/en-us/security/blog/2026/10/29/tracking-ai-adoption-in-north-korean-threat-actor-tradecraft/). These actors now use generative AI to automate lure generation and develop malicious scripts. This hunt provides a systematic way to find the artifacts of these automated workflows, which often evade individual signature-based rules by operating at a scale and speed that manual attackers cannot match.

### The Hypothesis

An intruder uses generative AI to produce high-volume tailored lures and trojanized repositories, subsequently deploying agentic frameworks like ARTEX for automated reconnaissance and persistence.

### How the hunt flows

#### Scoping the Surface

The first phase identifies the environment's most likely targets. The first query focuses on software inventory, listing hosts that run development tools like Git, Python, or VS Code, as well as AI-assisted coding tools like Cursor. This baseline identifies the primary attack surface for supply chain and remote-worker operations, allowing analysts to prioritize their investigation.

#### Detecting Initial Access

The hunt then looks for evidence of high-volume social engineering and trojanized code delivery. An adversary uses AI to generate dozens of tailored lures, such as interview preparation or salary detail documents, which appear in bursts across downloads and desktop folders. Simultaneously, the hunt checks for Git clone activity originating from external or unusual domains, which often indicates the delivery of AI-refactored trojanized logic.

#### Identifying Agentic Reconnaissance

Once an intruder gains access, the focus shifts to the agentic footprint of frameworks like ARTEX. The hunt identifies automated command bursts where a single parent process executes at least three distinct reconnaissance tools — such as whoami, net, and tasklist — within a sixty-second window. This specific combination of variety and speed differentiates AI-driven agents from typical manual attacker behavior.

#### AI-Assisted Persistence

In the final phase, the hunt searches for persistence mechanisms potentially created with AI development assistants. It identifies new services that execute binaries from user-writable paths like AppData or temporary directories. These scripts are often refactored by AI to evade standard detection, making the location and creation method more important than the specific file hash.

### What the hunt cannot see

This hunt has limited visibility on hosts not enrolled in the endpoint monitoring platform. If an adversary compromises a personal machine or a shadow-IT host to deliver lures, the initial file bursts will remain invisible. Furthermore, while the hunt identifies Git clones, it cannot audit the specific contents or modifications within private repositories without supplemental cloud API logs. This creates a gap in verifying whether an actor exfiltrated source code or committed malicious changes back to the origin.

### How to run it

This hunt is an open hunt.md playbook. You can import the markdown file directly into Huntbase or any hunt.md-aware runtime. The playbook includes the logic to scope development environments, detect automated PDF creation bursts, and identify the high-velocity command execution typical of agentic frameworks.
