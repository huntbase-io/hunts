# Hunting TeamFiltration Spraying and Data Harvesting in Microsoft 365

### Why Now

Proofpoint recently detailed a campaign where the TeamFiltration framework compromised several Microsoft 365 accounts. The adversary targeted service accounts using default passwords, bypassing standard identity protections. This hunt provides a method to find similar activity in your environment by looking for the specific patterns of TeamFiltration spraying and post-compromise data harvesting. TeamFiltration Campaign Compromises Seven Microsoft 365 Accounts Using Default Passwords: https://www.proofpoint.com/us/newsroom/news/teamfiltration-campaign-compromises-seven-microsoft-365-accounts-using-default

### Hypothesis

An adversary uses the TeamFiltration framework to spray M365 service accounts with default passwords from AWS infrastructure, subsequently harvesting data via the Graph API and probing internal VPN endpoints.

### Phase 1: Scoping VPN Gateways

The first phase identifies your VPN and proxy gateways. By searching for devices handling SAML authentication and specific VPN paths, the hunt builds a scoping list. This list ensures later steps can accurately detect if an attacker pivoted from a cloud compromise to probing your internal perimeter.

### Phase 2: Correlating Spray Patterns

The hunt then correlates authentication patterns in Entra ID. It runs two parallel queries: one to find source IPs with high failure rates and another to find successful logins to service accounts without MFA. This phase identifies the broad spraying activity and the specific accounts that failed to stop the breach.

### Phase 3: Assessing Compromise Impact

An analyst or automated agent assesses the impact by joining these results. The hunt identifies a beachhead when a single source IP shows both high-volume failures across multiple accounts and a successful login to a vulnerable service account. This step filters out noise and focuses the investigation on confirmed compromises.

### Phase 4: Investigating Post-Breach Activity

The final phase tracks post-breach activity across cloud and network surfaces. It queries for Microsoft Graph API token requests and file discovery in SharePoint or OneDrive. Simultaneously, it checks for HTTP requests from the attacker IPs to the VPN gateways identified in the first phase, uncovering attempts to move deeper into the network.

### Hunt Blind Spots

This hunt faces two primary blind spots. First, cloud audit logs often have ingestion latency, meaning an attacker might harvest data before the activity appears in your telemetry. Second, if your proxy does not inspect TLS traffic to VPN gateways, the hunt cannot see the specific URI paths used during probing, limiting the visibility of the internal pivot attempts.

### Running the Playbook

You can run this hunt using any hunt.md-aware runtime or by importing it into Huntbase. The playbook guides you through each phase, from initial scoping to automated compromise assessment. After running the queries, you can use the built-in decision steps to suspend compromised accounts and initiate a manual review of accessed files.
