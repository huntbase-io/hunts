# Hunting Web Shell Ingress on Management Platforms

### Why this hunt
We developed this hunt following the Huntress report [Determined Attacker Uploads Malicious Webshells to Parks and Rec Management Platform Servers](https://www.huntress.com/blog/parks-recreation-platform-webshell-attack). The report describes an adversary targeting municipal recreation platforms by exploiting file upload vulnerabilities. This hunt is designed to detect the specific sequence of events leading to a web shell compromise: boundary probing, authentication abuse, and finally, the presence of executable scripts in member-facing upload directories.

### The Hypothesis
The adversary attempts to breach the web application by probing for vulnerabilities and brute-forcing login pages. They target the `/management/login.aspx` and `/info/household/login.aspx` endpoints to gain access or identify weaknesses. Once a foothold is established or an exploit is triggered, they drop web shells in the `/documents/MemberFiles/` directory to maintain persistence and execute commands.

### Phase 1: Boundary Probing
The hunt begins by examining `hb_http_activity` logs for signs of application profiling. We look for tilde enumeration, WebDAV `OPTIONS` requests, and unusual URI stems. By identifying the source IPs involved in these requests, we establish a list of potentially malicious actors currently scanning the infrastructure. This initial scoping phase narrows the investigation to hosts showing active signs of interest from external actors.

### Phase 2: Corroborating Ingress
We then move to a parallel examination of authentication and file system metadata. One query monitors `hb_auth_signin` for high-volume login failures against the management interface, focusing on the same hosts identified in the scoping phase. Simultaneously, we scan `hb_file_activity` for the creation of `.aspx` or `.ashx` files within the `MemberFiles` directory. These directories are intended for images or PDFs; the appearance of active scripts is a strong indicator of unauthorized ingress.

### Phase 3: Automated Triage
An automated agent correlates the results from the previous phases. It links the source IPs from the HTTP probes to the timing of the authentication failures and the subsequent file creations. This correlation is vital for a hunt, as it allows us to differentiate between a legitimate user misusing a directory and an external attacker following a structured exploitation path. The agent provides a verdict based on this forensic chain, allowing analysts to focus on confirmed compromises.

### Blind Spots and Limitations
This hunt relies heavily on the presence of IIS W3C logs and file creation telemetry. If the web server does not log URI stems or if the `hb_http_activity` surface is not being ingested, the initial probing signal will be lost. Furthermore, this hunt examines metadata rather than file content. While the creation of an ASPX file in a member directory is highly suspicious, manual inspection of the file content is still necessary to determine the shell's specific capabilities or confirm the presence of malicious code.

### How to run this hunt
This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any compatible `hunt.md` runtime. The playbook includes parameters for lookback windows and specific web shell filenames identified in recent attacks. Using the playbook format ensures the correlation between probing and file creation is handled consistently across different environments.
