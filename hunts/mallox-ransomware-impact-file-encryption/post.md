# Hunting Mallox Ransomware Encryption via Volumetric File Activity

### Why Now

Recent research by Sekoia [Mallox ransomware affiliate leverages PureCrypter](https://blog.sekoia.io/mallox-ransomware-affiliate-leverages-purecrypter-in-microsoft-sql-exploitation-campaigns/) highlights how Mallox affiliates are using PureCrypter to deliver payloads after initial MSSQL exploitation. While initial access and persistence are critical to track, the final impact stage—encryption—remains the most visible and damaging phase. We have designed this hunt to focus on the behavioral footprints of that encryption process.

### The Hypothesis

We hypothesize that an intruder has successfully executed a Mallox payload from a user-writable path (like `%AppData%` or `%ProgramData%`), resulting in high-volume file creation, modification, or renaming consistent with AES encryption. Because Mallox rotates its payload names (e.g., `Ydxhjxwf.exe`), we cannot rely solely on filename lookups; instead, we look for the intersection of rare execution and mass impact.

### How the Hunt Flows

The hunt begins with a scoping phase on the `hb_process_activity` surface. We identify all processes launched from directories where users have write permissions but shouldn't typically be running persistent binaries. This provides our base set of suspicious candidates for further analysis.

From there, the hunt pivots into a parallel evaluation of prevalence and impact. We stack-count the identified binaries across the fleet to find rare or unique payloads. Simultaneously, we examine the `hb_file_activity` surface to find processes within those writable paths that are performing a high volume of file operations—specifically creations, updates, or renames exceeding a defined threshold (defaulting to 500 events).

Finally, the triage phase correlates these two signals. A rare process (appearing on only one or two hosts) that is also responsible for a surge in file activity is flagged for immediate review. This behavioral correlation allows us to see through the 'noise' of legitimate updaters or local tools that might also live in AppData but lack the volumetric impact of ransomware.

### What the Hunt Cannot See

There are two primary blind spots to consider. First, if the ransomware logic is reflectively loaded and executed entirely in memory without a persistent binary on disk at the time of the hunt, our prevalence stacking may return zero results. Second, if the EDR or agent telemetry is restricted to system volumes, encryption occurring on secondary drives or network shares may be invisible to the volumetric query.

### How to Run This Hunt

This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any security runtime that supports the `hunt.md` standard. Because this hunt targets the 'impact' stage, it is best run on a frequent schedule (e.g., daily) or triggered by alerts of suspicious MSSQL activity.
