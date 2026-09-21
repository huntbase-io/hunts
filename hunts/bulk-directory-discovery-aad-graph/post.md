# Hunting for Bulk Directory Discovery via Legacy Azure AD Graph API

### Why this hunt

Microsoft recently introduced the ability to ingest activity logs for the legacy Azure AD Graph API, as detailed by Elastic Security Labs in [Azure AD Graph Activity Logs: Ingestion and threat detection](https://www.elastic.co/security-labs/blog/aad-graph-activity-logs-threat-detection). While modern environments favor Microsoft Graph, adversaries still use the legacy `graph.windows.net` endpoint. This legacy interface has historically lacked the visibility required to detect bulk enumeration. This hunt provides a structured path to find that activity across authentication, network, and endpoint surfaces.

### The hypothesis

An adversary uses legacy Azure AD Graph API endpoints and known offensive Client IDs to perform bulk directory enumeration, specifically targeting internal API versions that expose sensitive authentication methods.

### How the hunt flows

The hunt begins by scoping successful authentication events. A query searches the `hb_auth_signin` surface for tokens issued for the legacy Graph resource. It specifically filters for Client IDs associated with known offensive tools and the Azure CLI. An analyst or agent evaluates these leads to find sessions that do not match the expected user profile or host location.

Once a suspicious lead exists, the hunt executes two parallel searches. First, it identifies rare User-Agents within the `hb_http_activity` surface targeting `graph.windows.net`. By counting unique users per User-Agent, the hunt isolates strings used by only one or two identities, which often reveals custom Python scripts or tools like ROADrecon. Second, the hunt searches the `hb_script_activity` surface on endpoints for script blocks containing references to the legacy API or the internal-only 1.61-internal version.

The final phase synthesizes these findings. An analyst triages the combined results to confirm whether the API traffic corresponds to the script execution on the beachhead host. If the activity appears malicious, the hunt provides steps to isolate the host and revoke Entra ID refresh tokens for the compromised account.

### What the hunt cannot see

This hunt relies heavily on the `AzureADGraphActivityLogs` category. If an organization has not enabled this diagnostic setting in the Entra ID portal, server-side API activity remains invisible. Additionally, if the environment lacks HTTP telemetry or HTTPS decryption, the hunt cannot inspect the specific URL parameters or User-Agents required to identify the use of internal API versions.

### How to run this hunt

This hunt is provided as an open `hunt.md` playbook. It follows a machine-readable format that imports directly into Huntbase or any other `hunt.md`-aware runtime. Because this hunt correlates data across three distinct surfaces — authentication logs, server-side activity logs, and endpoint script blocks — it identifies patterns that a single, isolated detection rule would likely miss.
