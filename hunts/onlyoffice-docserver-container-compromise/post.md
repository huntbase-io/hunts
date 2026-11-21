# Hunting ONLYOFFICE DocBuilder Exploitation and Container Root Escalation

### Why now

Rapid7 recently detailed a vulnerability chain in ONLYOFFICE Docs (https://www.rapid7.com/blog/post/ve-from-view-only-access-to-container-root-five-vulnerabilities-in-onlyoffice-docs-fixed) that permits complete container takeover. An attacker starts with simple view-only access to a document and finishes as root. This hunt provides a technical path to identify this exploitation in your document infrastructure.

### Hypothesis

An attacker with view-only document access chains an authorization bypass in the DocBuilder API with a native file read to forge credentials and escalate to root via a maintenance script.

### How the hunt flows

The hunt begins by scoping the environment for ONLYOFFICE Document Server installations. The first phase uses the hb_software_inventory surface to find packages older than version 10.0. This restricts the investigation to vulnerable hosts and reduces noise from patched systems. We focus on packages like onlyoffice-documentserver because the vulnerability resides in the core document handling logic. Since ONLYOFFICE is frequently integrated into suites like Zimbra or Nextcloud, we recommend running this across any Linux host facilitating document previews.

After scoping, the hunt moves to web and file telemetry. It identifies rare requests to the /docbuilder endpoint containing JWT tokens in the url_query using hb_http_activity. In parallel, it monitors for unauthorized access to sensitive configuration files like local.json via hb_file_activity. If an attacker reads local.json, they obtain the signing keys required to forge administrative tokens. The hunt identifies when ONLYOFFICE processes or the service account touch these files, or system files like /etc/passwd.

The third phase examines the behavior of the ds service account using hb_process_activity. This account runs the application and should not typically execute interactive shells or network utilities. The hunt flags any instances of the ds user spawning bash, python, or curl. This activity suggests the attacker has moved from builder API interaction to active code execution.

The final phase looks for the privilege escalation attempt in hb_process_activity. The documentserver-flush-cache.sh script is a sudo helper that runs without a password. An attacker can inject commands into the --hash parameter, which the script passes to the sed utility. By using the sed e flag, the attacker executes arbitrary shell commands as root. The hunt specifically identifies this pattern in process command lines using the flush-cache script.

### Blind spots

This hunt has two main visibility gaps. If the endpoint agent lacks visibility into container namespaces, the process-level activity by the ds user and the root helper will not appear in the telemetry. Additionally, most environments do not log HTTP POST bodies. Because the specific DocBuilder scripts are passed in these bodies, the hunt relies on URL-based tokens and subsequent file activity to infer the nature of the request.

### How to run

This is a hunt.md playbook. It imports into Huntbase or any hunt.md-aware runtime for immediate use. Analysts should focus on the correlated verdict from the final triage step to distinguish true compromise from maintenance windows.
