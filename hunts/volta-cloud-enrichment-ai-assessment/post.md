# Hunting for VOLTA Infostealer AI-Driven Victim Prioritization

### Why now

Recent analysis from Talos, titled [Appraisal by AI: Model-driven victim prioritization in the VOLTA infostealer](https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/), describes a shift in how infostealer operators manage high-volume data. Instead of manual review, the VOLTA malware uses stolen session tokens to query consumer APIs for enrichment and then feeds that data to Large Language Models (LLMs) to determine which victims have the most valuable assets. We published this hunt to identify this specific post-harvesting lifecycle.

### The Hypothesis

An intruder uses stolen session tokens to query third-party APIs for victim data enrichment and calls LLMs to prioritize assets for exfiltration. This activity creates a distinct footprint of specific DNS resolutions and API interactions that deviate from standard developer or user behavior.

### How the hunt flows

The hunt begins with a scoping query into DNS activity. The first step identifies hosts resolving domains associated with session-based enrichment or AI prioritization, such as openrouter.ai, doordash.com, and rolimons.com. These resolutions serve as the initial lead for identifying potentially compromised endpoints where session theft has already occurred.

Once the hunt identifies candidate hosts, it moves to a parallel verification phase. One query branch inspects HTTP activity for POST requests directed at OpenRouter or other enrichment endpoints. Simultaneously, a second branch searches the file system for local artifacts like Identity_Report.txt or AI_Analysis.txt. The adversary uses these files to stage the victim dossier before exfiltration.

In the final phase, an automated agent weighs the evidence from all surfaces. The agent reviews the DNS leads, HTTP POSTs, and file artifacts to determine if the host exhibits the full VOLTA behavior pattern. This correlation is necessary because individual indicators, like a DNS lookup for an AI service, are common on developer workstations and would produce too many false positives on their own.

### What this hunt cannot see

The hunt faces two primary blind spots. First, it requires HTTP transparency to see the contents and method of requests to OpenRouter. If the environment lacks decrypted proxy logs or endpoint HTTP instrumentation, the hunt only sees the DNS resolution, which is a weaker signal. Second, VOLTA attempts to delete its local report files. If the file activity collection is snapshot-based rather than real-time, the creation of Identity_Report.txt may go unrecorded.

### How to run it

This hunt is available as an open `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the `hunt.md` format. The playbook includes the SQLite queries for DNS, HTTP, and file surfaces, and provides the logic for an agent to triage the results. Because this hunt focuses on post-harvest behavior, it is best run on hosts where credential-stealing activity is already suspected.
