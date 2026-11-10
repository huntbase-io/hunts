# Hunting for AI-Driven Infostealer Lifecycles

### Why now
Cisco Talos recently detailed the evolution of modern infostealers in their report, [Bring a tent, I've got the coffee: Lessons from it-sa](https://blog.talosintelligence.com/bring-a-tent-ive-got-the-coffee-lessons-from-it-sa/). The analysis highlights how tools like the VOLTA infostealer now use AI to speed up the monetization of stolen data. This shift requires a hunt that looks beyond the initial infection to find the automated prioritization and cleanup phases.

### The hypothesis
An intruder deploys an infostealer that launches headless browser sessions to harvest credentials and cryptocurrency wallets. The malware then exfiltrates this data to LLM providers to prioritize high-value targets before performing automated cleanup via self-deletion.

### How the hunt flows
The hunt starts by scoping the environment. The first query checks the software inventory for any host with Chrome or Chromium installed. This narrows the focus to systems capable of supporting the infostealer's headless browser harvesting techniques.

The second phase investigates execution and harvesting in parallel. The hunt searches process activity for the `--headless` flag and identifies rare parent processes that do not match known automation servers. Simultaneously, it monitors file activity for access to sensitive files like `wallet.json`, `seed.txt`, or browser login data.

Next, an agent triages these results to find hosts where headless execution correlates with unauthorized file access. If a host appears suspicious, the hunt pivots to network telemetry. It searches DNS logs for connections to LLM API domains like OpenAI, Anthropic, or Mistral, which indicates the adversary is using AI to analyze the stolen data.

The final phase looks for evasion. The hunt identifies instances where a process deletes its own executable. This self-deletion event, occurring after suspicious harvesting and network activity, confirms the completion of the malware lifecycle.

### What the hunt cannot see
This hunt has two primary blind spots. First, standard endpoint logs cannot see the specific interactions occurring inside a headless browser session. While we see the connection to a webmail domain, we cannot see the specific search terms used to find receipts or addresses. Second, the hunt depends on process and file telemetry. If an adversary operates on an unmanaged system without an endpoint agent, the harvesting remains invisible until exfiltration occurs at the network layer.

### How to run it
This hunt is available as an open `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the `hunt.md` standard. Because headless browser use is common in development environments, the hunt includes parameters to exclude known legitimate automation parents during the investigation phase.
