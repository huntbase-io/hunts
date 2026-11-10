# Hunt for Gorbag Browser Data Harvesting and Exfiltration

### Strategic Intel Theft

A recent report from ESET Research, [Gorbag: Orcs at the border harvesting intelligence from Ukraine](https://www.welivesecurity.com/en/eset-research/gorbag-orcs-border-harvesting-intelligence-ukraine/), describes a targeted intelligence-gathering campaign. The adversary, likely Russia-aligned, focuses on Ukrainian justice and defense sectors to harvest credentials and VPN configurations. Their toolkit, including BeautyStealer, operates with a 'one-pass' philosophy: access the data, archive it, send it, and delete the evidence. We designed this hunt to find this specific progression of behaviors across an enterprise fleet.

### The Hypothesis

A Russia-aligned actor is stealing browser credentials and VPN configurations, exfiltrating them via Telegram or direct IP, and then deleting the evidence from disk. This activity often precedes more significant intrusions by providing the adversary with the necessary access for lateral movement and strategic data collection.

### How the Hunt Flows

The lead query identifies non-browser processes that read sensitive browser credential databases or VPN configuration files. It targets SQLite databases for Chrome and Edge, alongside OpenVPN and Cisco configuration files. A hit here indicates that a process other than the legitimate application is interested in identity secrets.

Once the hunt identifies suspicious access, it executes two parallel queries to build evidence. The first branch looks for rare process behaviors, specifically the creation of RAR or ZIP archives and file deletions within the ProgramData directory. This pattern matches the staging and cleanup behavior observed in BeautyStealer infections. The hunt stacks these events by host count to highlight outliers.

The second parallel branch examines network telemetry. It matches outbound connections against known command-and-control (C2) IPs and domains provided in the ESET report. It also flags any process communicating with the Telegram API (api.telegram.org), which the actor uses as a convenient, encrypted exfiltration channel.

Finally, an analyst or automated agent weighs these signals. A host where a rare process read a browser database, created a ZIP file, and then connected to Telegram represents a confirmed intrusion. This multi-stage approach ensures that the noise of legitimate administrative tools does not drown out the actual threat.

### Blind Spots

This hunt relies on specific telemetry. If the environment does not have file read-access auditing enabled for user profile paths, the lead query will return no results. Without this visibility, unauthorized access to SQLite databases remains invisible. Additionally, while we identify traffic to Telegram, the use of RC4 encryption over HTTPS prevents us from seeing exactly what data was stolen without full SSL inspection.

### Running the Hunt

This hunt is available as an open `hunt.md` playbook. You can import it directly into Huntbase or any other `hunt.md`-aware runtime. It uses a 14-day lookback by default and allows you to scope the search to specific high-value hosts or departments most likely to be targeted by Gorbag.
