# Hunting for Spring Ring Microsoft Teams Vishing and Delivery Patterns

The Spring Ring campaign, documented by Unit 42 in their article "Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams" (https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/), represents a shift in initial access tactics. Adversaries are moving away from heavily filtered email environments and toward trusted collaboration platforms like Microsoft Teams.

Our hypothesis is that an adversary uses external Teams accounts to masquerade as corporate IT support. They initiate calls or chats to coerce users into running remote management software or downloading payloads from attacker-controlled S3 buckets. Because the tools used—such as Quick Assist or AnyDesk—are often legitimate, and the domains are hosted on Microsoft infrastructure, detection requires a behavioral approach rather than simple indicator matching.

The hunt begins by scoping the environment to hosts where Microsoft Teams is actively installed. This focuses telemetry analysis on the relevant population and provides a baseline for where vishing is even possible within the organization.

Next, the hunt moves into a parallel corroboration phase. We look for DNS resolutions of impersonated .onmicrosoft.com domains (e.g., "itprotectiondepartment.onmicrosoft.com") and the specific C2 domain "san-sid.com". Simultaneously, we monitor for HTTP requests to AWS S3 buckets that match the campaign's naming conventions for tailored executables, and the execution of RMM tools like Quick Assist or TeamViewer.

The final stage of the logic is temporal triage. A single DNS resolution or a one-off launch of Quick Assist is often benign. However, when these events occur on the same host within a 60-minute window, the probability of a successful vishing attempt increases significantly. Our hunt uses an agent to link these disparate telemetry sources—DNS, HTTP, and Process—into a single prioritized event for analyst review.

There are specific blind spots to consider. This hunt relies on network and endpoint telemetry; it cannot see the actual content of the Teams chat or the audio of the vishing call. Without Unified Audit Logs or Teams Activity Logs, we cannot definitively prove a message was received, only that the host resolved the attacker's domain.

This playbook is formatted as a hunt.md file. It can be imported into any runtime compatible with the hunt.md standard, such as Huntbase, allowing practitioners to automate the correlation of these social engineering lures with technical execution.
