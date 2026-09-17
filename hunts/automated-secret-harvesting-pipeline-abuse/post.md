# Hunting Automated Secret Harvesting and Agentic Pipeline Abuse

The speed of modern intrusions is increasing as attackers integrate automated agents into their workflows. A recent investigation by [Unit 42](https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/) highlighted an incident where an AI-assisted attacker systematically harvested secrets to pivot through a developer's environment. This hunt is designed to find the technical side-effects of this automation.

### The Hypothesis
We hypothesize that an automated agent is systematically scraping local code repositories for secrets and using them to pivot into secrets managers or CI/CD pipelines. This behavior is evidenced by bursty file activity and rapid authentication attempts that exceed typical human speed.

### How the Hunt Flows
The hunt begins by narrowing the scope to DevOps and developer systems. We use software inventory data to identify hosts running tools like Git, Terraform, or Docker, as these systems are the primary targets for credential harvesting in automated attacks.

Once the scope is defined, we move into a parallel evidence-gathering phase across three surfaces. First, we examine file activity for processes touching high volumes of sensitive files, such as `.git/config` or `.ssh/id_rsa`, within a narrow time window. Simultaneously, we look for bursty authentication patterns, specifically rapid transitions between success and failure states that suggest automated credential testing.

Finally, we look for "agentic artifacts." Automated loops often produce structured communication files, such as Markdown reports or unusual Python cache files in temporary directories. These artifacts serve as the hand-off points between different stages of an automated attack. The hunt concludes by using an agent to weigh these disparate signals—file reads, auth bursts, and artifacts—to distinguish between a busy developer and a malicious automated process.

### What This Hunt Cannot See
There are two primary blind spots to consider. First, if the secret harvesting phase occurred slowly over several weeks, it may fall outside the 14-day lookback window defined in this playbook. Second, while we can observe the authentication attempts to services like Hashicorp Vault or AWS Secrets Manager, we cannot see the specific secret values being accessed without native audit logs from those products.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported into Huntbase or any runtime that supports the `hunt.md` standard. Because it correlates activity across multiple surfaces—file, authentication, and inventory—it provides a more holistic view of automated abuse than a single detection rule.
