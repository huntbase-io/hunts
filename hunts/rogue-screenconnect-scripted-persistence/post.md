# Hunting Rogue ScreenConnect Persistence and Power BI Phishing Artifacts

### Why Now
Adversaries are abusing trusted cloud infrastructure to bypass traditional email filters. A recent report by Huntress — [Phishing Campaign Abuses Microsoft Power BI to Deploy Rogue RMMs](https://www.huntress.com/blog/screenconnect-power-bi) — details how attackers use Power BI domains to host rogue RMM installers. Once the installer runs, the adversary uses PowerShell to rotate instances and establish persistent access while hiding their presence with custom evasion tools.

### The Hypothesis
An adversary is using trusted Power BI domains to stage rogue ScreenConnect installers, which then use PowerShell scripts to rotate instances and establish persistent tasks while cloaking their presence with the HideUL evasion tool.

### How the Hunt Flows
The hunt begins by scoping endpoints. The first query filters for ScreenConnect activity where the binary or its installer executes from a temporary directory or user download folder. This narrows the fleet to hosts showing atypical RMM deployment patterns.

Once scoped, the hunt gathers early-stage evidence through two parallel paths. It checks DNS activity for resolutions of known rogue relay domains and searches script logs for deployment commands. It specifically looks for the script names LyN03DvVjUKPrun.cmd or SCAutoFix.ps1 and the internal logic used to swap RMM instances.

After assessing the early-stage infection, the hunt pivots to follow-on persistence. It identifies rare scheduled tasks that execute these deployment scripts, specifically looking for the task name SCAutoRepairEvery2Min. This step uses a frequency analysis to find tasks that appear on fewer than three hosts across the environment.

Finally, the hunt checks for active defense evasion. It searches for the execution of HideUL_x64.exe on the potentially compromised hosts. The presence of this binary alongside rogue RMM activity confirms an active attempt to cloak the intrusion.

### Blind Spots
This hunt relies on PowerShell Script Block Logging (hb_script_activity) to see the specific commands within the SCAutoFix.ps1 script. Without this logging, an analyst can see the script executed but cannot verify the specific modifications made to the ScreenConnect instances. Additionally, short DNS retention windows may hide initial contact with relay domains if the infection occurred several weeks prior to the hunt.

### How to Run This Hunt
This hunt is available as an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. The playbook provides the structured logic to pivot from initial scoping to final triage, ensuring that analysts only investigate hosts where the full chain of deployment, persistence, and evasion is present.
