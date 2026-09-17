# Hunting for Icarus Salesforce API Data Harvesting Automation

### Why Now

Recent analysis from Datadog Security Labs in their article, [Detecting the Klue supply chain attack in Salesforce](https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/), detailed how threat actors leveraged a supply chain compromise to harvest sensitive CRM data. The actor, tracked as Icarus, utilized automated scripts to systematically dump records using valid but compromised credentials. This hunt provides a structured approach to identifying these automated harvesting patterns within your environment.

### The Hypothesis

We hypothesize that a threat actor is using automated Python scripts and compromised tokens to exfiltrate CRM data from Salesforce via specific REST API query endpoints and QueryMore operations. Because legitimate integrations often use similar methods, the hunt relies on identifying the specific behavioral deviations—such as rare User-Agent strings and unauthorized infrastructure—associated with the Icarus group.

### How the Hunt Flows

The hunt begins by scoping the estate for hosts with Python installed. While the primary activity is network-based, understanding which endpoints possess the capability to run the actor's observed scripts helps narrow the triage focus and provides context for subsequent findings.

Next, the hunt pivots to network-level HTTP activity. We specifically look for outbound requests targeting Salesforce REST API query endpoints (v59.0) and the use of the `QueryMore` paging operation. We look for the actor's known User-Agent strings, including `5238` and various `python-urllib` versions, which are common in their automated toolset.

To reduce noise, we perform a prevalence analysis on these User-Agents. By stack-counting Python-based automation across the fleet, we can isolate rare versions that deviate from standard internal utilities. This is combined with a check against confirmed malicious infrastructure IPs identified in the Klue investigation, providing high-confidence corroboration for any observed API activity.

Finally, the hunt synthesizes these signals. If a host displays a combination of Salesforce query patterns, rare automation signatures, and connections to known C2 infrastructure, it is prioritized for immediate triage and session revocation.

### What the Hunt Cannot See

This hunt has two primary blind spots. First, without full TLS decryption or endpoint-level HTTP body inspection, we cannot see the specific content of the API queries. We may see that a query occurred, but we cannot confirm if the actor was targeting specific sensitive entities like 'Opportunities' or 'Contacts' using the `SELECT FIELDS(STANDARD)` syntax. 

Second, without access to HTTP response codes and messages, we cannot identify 'noisy' discovery attempts where the actor might have triggered `ApiException` errors. We are limited to observing the initiation and destination of the traffic rather than the success or failure of the specific data request.

### How to Run This Hunt

This hunt is provided as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime that supports the `hunt.md` standard. The playbook includes the necessary SQL queries for software inventory, HTTP activity, and network connection surfaces. Once imported, you can adjust the `lookback_days` parameter to fit your data retention policy and execute the steps as a guided workflow.
