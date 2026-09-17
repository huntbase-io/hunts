# Spring Ring Campaign: Persistence and Headless Browser Hijacking

The "Spring Ring" campaign, recently detailed by [Unit 42](https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/), leverages the social engineering of users over Microsoft Teams to deploy malware. Because the initial contact occurs via voice or chat, visibility into the initial access phase is often limited for security teams. This hunt focuses on the subsequent endpoint activity: the establishmen of persistence and the hijacking of user sessions through browser manipulation.

### The Hypothesis
Our hypothesis is that an adversary has successfully established a foothold after a vishing call by dropping duplicated executables into temporary directories. To maintain access and facilitate session hijacking, they are utilizing a headless instance of Microsoft Edge with a sideloaded extension, allowing them to operate without user interaction or visible browser windows.

### How the Hunt Flows
The hunt begins with a scoping phase focused on known artifacts. We look for file creation events in temporary directories that match the `vhlp-*.exe` and `scnr-*.exe` naming conventions identified in the Spring Ring campaign. This phase provides the initial list of potentially compromised endpoints based on specific campaign indicators.

Following the identification of these artifacts, the hunt pivots to behavioral analysis of process execution. We specifically examine instances of `msedge.exe` that are launched with both the `--headless` and `--load-extension` flags. While developers sometimes use headless browsers for testing, the combination of these flags on a standard user workstation is a high-confidence signal for sideloading malicious extensions used in session hijacking.

To ensure we do not miss variations of the campaign using different naming conventions, the final phase involves stack-counting rare executables running from temporary directories. By filtering for binaries seen on a very small number of hosts (e.g., three or fewer), we can surface unique payloads that may be randomized per-infection but still exhibit the same staging behavior as the Spring Ring artifacts.

### What This Hunt Cannot See
There are inherent blind spots in this design. First, if endpoint telemetry does not include process command-line arguments, the behavioral signals for Edge hijacking will be invisible. Second, while we can detect that an extension was loaded, process telemetry alone does not reveal the contents of that extension. Determining if the extension is scraping credentials or performing session relay requires subsequent forensic collection of the extension files from the local app data folder.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It is designed to be imported directly into Huntbase or any runtime capable of parsing the hunt.md format. By following the structured steps, analysts can move from broad scoping to targeted behavior analysis and then into containment actions like host isolation if malicious persistence is confirmed.
