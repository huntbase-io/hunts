# Detecting Teams Impersonation and Portable Runtime Execution

### Why This Hunt Matters

Microsoft recently detailed an intrusion path in [From help desk impersonation to AD CS abuse](https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/) that bypasses traditional email security. The adversary uses Microsoft Teams to impersonate help desk staff and lures users into a remote support session. This hunt identifies the specific transition where an external actor moves from a chat window to executing commands on a workstation.

### The Hypothesis

An intruder impersonates help desk staff via Microsoft Teams to establish a remote support session through Quick Assist. After gaining access, the adversary stages portable runtimes in a user-writable directory to execute system discovery commands and prepare for lateral movement.

### How the Hunt Flows

The hunt begins with a scoping phase to identify the potential beachhead. The first query searches for any host that recently executed `quickassist.exe`. This provides a baseline of all remote support activity, which the analyst later narrows down by looking for users who did not have an open support ticket.

Next, the hunt gathers context through two parallel queries. One query identifies Microsoft Teams sign-ins where the home tenant does not match the resource tenant, indicating contact from an external organization. The second query searches for the creation of new directories within user profiles that follow specific naming patterns, such as folders prefixed with "KB". These folders often host the adversary's toolkit.

In the third phase, the hunt pivots to behavioral execution. It looks for portable runtimes like Python, Bun, or Java executing from the previously identified staging directories. It specifically alerts when these runtimes launch system discovery utilities such as `ipconfig.exe`, `tasklist.exe`, or `whoami.exe`. This phase links the suspicious directory creation to actual hands-on-keyboard activity.

Finally, an analyst or automated agent weighs the evidence. If a host shows cross-tenant Teams activity followed by a Quick Assist session and portable runtime execution, it meets the criteria for a malicious verdict.

### What the Hunt Cannot See

This hunt relies on endpoint telemetry. If a user launches Quick Assist on an unmanaged or personal device that then accesses corporate resources, the initial execution remains invisible. Additionally, the hunt identifies the presence of external Teams authentications but cannot see the specific content of the messages sent to the user. The analyst must verify the social engineering context manually through chat logs if available.

### How to Run It

This hunt is packaged as a `hunt.md` playbook. You can import it directly into Huntbase or any security platform that supports the `hunt.md` format. The playbook includes the logic for the initial scoping, the behavioral pivots, and the final triage steps. Use the provided parameters to adjust the lookback window or to add specific staging folder patterns observed in your environment.
