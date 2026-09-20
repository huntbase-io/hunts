# Hunting Abused RMM Tools via DNS Prevalence and HTTP Metadata

### Why now

Adversaries frequently abuse legitimate software to maintain persistence and move laterally without triggering endpoint alerts. Red Canary recently detailed this challenge in their article, The dual-use dilemma: Rethinking detection for remote access tool abuse (https://redcanary.com/blog/security-operations/rmm-detection/). Because RMM tools like NetSupport, Atera, and Syncro are signed and perform standard administrative tasks, many security products treat them as inherently safe. This hunt addresses that gap by focusing on the network footprints these tools leave behind.

### The hypothesis

An adversary uses unauthorized RMM tools for command and control. These tools are detectable via rare DNS lookups to known RMM infrastructure and specific HTTP User-Agent strings that identify the client software. While an IT department might use one or two of these tools globally, an attacker-controlled instance usually appears as a unique or rare connection in the environment.

### How the hunt flows

The first phase scopes the estate for any host communicating with known RMM domains. This query acts as a gate to limit the data volume for follow-on steps. It scans the DNS activity for a curated list of domains associated with tools like ScreenConnect, AnyDesk, and various MSP platforms.

Once the hunt identifies lead hosts, it branches into two parallel investigative paths. One path calculates the prevalence of each RMM domain across the entire fleet. If a domain appears on hundreds of hosts, it likely belongs to a sanctioned IT tool. If it appears on only one or two hosts, it warrants immediate investigation.

The second path inspects HTTP telemetry for the same hosts. It looks for identifying User-Agent strings known to belong to RMM clients. This metadata provides high-confidence evidence that a specific tool is active on the host, even if the binary name has been changed by the adversary.

In the final phase, an agent evaluates the combined evidence from the DNS and HTTP queries. The agent compares the rarity of the network connections against the specific metadata found to determine if the activity aligns with a malicious intrusion. An analyst then performs a forensic review of the suspicious binaries and their installation origin.

### What this hunt cannot see

This hunt has two primary blind spots. First, if an RMM tool uses DNS-over-HTTPS (DoH) to resolve its command-and-control infrastructure, the DNS queries will not appear in standard network-level or endpoint-based DNS logs. Second, the hunt relies on the presence of HTTP metadata. If the RMM tool uses encrypted custom protocols or if the environment lacks HTTP inspection, the corroboration step will provide no results, leaving the hunt to rely solely on DNS prevalence.

### How to run it

This hunt is available as an open hunt.md playbook. You can import this file into Huntbase or any hunt.md-aware runtime to execute the queries and automated triage steps. The playbook includes the necessary SQL queries and agent instructions to guide you through the initial scoping to the final host isolation if a threat is confirmed.
