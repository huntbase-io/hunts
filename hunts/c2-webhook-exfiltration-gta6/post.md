# Hunting Multi-Protocol C2 and Discord Exfiltration in Fake Software Bundles

## Why This Hunt Matters

High-profile software releases often serve as effective lures for malware campaigns. Recent research by Huntress, [Grand Theft Auto VI hype leads to malware](https://www.huntress.com/blog/fake-gta6-download-malware-analysis), details a campaign where fake game installers deliver a destructive bundle including NJRAT, DCRAT, and the Mercurial Grabber. While initial detections often focus on the installer's file hash or the mounting of ISO files, these indicators are easily rotated. This hunt focuses on the more stable network behaviors of the malware’s command-and-control (C2) and exfiltration phases.

## The Hypothesis

We hypothesize that an adversary is using a combination of direct-IP C2 connections to AWS, protocol tunneling via ngrok on specific non-standard ports (12684), and Discord webhooks to exfiltrate stolen credentials. By looking for this specific combination of infrastructure and behavior, we can identify compromised endpoints regardless of the initial delivery mechanism.

## How the Hunt Flows

The hunt begins by scoping the environment to active Windows endpoints. Since the malware bundle is designed for Windows-based execution—often involving .NET payloads—this narrows the noise from other operating systems where ngrok or Discord usage might be more common for legitimate development work.

Next, we examine outbound network connections. We look specifically for two things: connections to hardcoded C2 IP addresses (specifically those identified in AWS and Russian infrastructure) and traffic to ngrok subdomains on port 12684. This specific port is a known default or common configuration for NJRAT variants used in these campaigns.

To add confidence, the hunt correlates these connections with DNS activity and HTTP patterns. We look for resolutions of specific Russian domains and the presence of rare Discord webhook URLs. Because Mercurial Grabber and similar infostealers use unique webhooks for each campaign or victim group, exfiltration via a Discord API path that is only seen on one or two hosts in the entire estate is a high-fidelity indicator of compromise.

Finally, the hunt triages these signals per host. A single connection to an AWS IP might be benign, but when paired with a unique Discord webhook request and a connection to a known tunneling port, it provides enough evidence for immediate isolation and forensic review.

## What This Hunt Cannot See

There are two primary blind spots to consider. First, if your telemetry only captures DNS logs without process-to-IP mapping, direct-IP connections used by NJRAT will be invisible. Second, without TLS inspection, we cannot see the specific data (like passwords or screenshots) being sent to Discord; we can only infer exfiltration based on the rarity and destination of the HTTP request.

## Running the Hunt

This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any security platform that supports the `hunt.md` standard. It is designed to be run periodically to catch infections that may have occurred after a user bypassed initial security warnings to install 'leaked' software.
