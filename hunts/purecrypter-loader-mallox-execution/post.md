# Hunting PureCrypter and Mallox Ransomware Activity

### Why now

Sekoia recently detailed how Mallox ransomware affiliates use PureCrypter to target MSSQL servers in their article, [Mallox ransomware affiliate leverages PureCrypter in MSSQL exploitation](https://blog.sekoia.io/mallox-ransomware-affiliate-leverages-purecrypter-in-microsoft-sql-exploitation-campaigns/). They use the loader to bypass defenses and pull down the final ransomware payload. This hunt focuses on identifying that loader activity before it transitions to full-scale encryption.

### The hypothesis

The adversary uses PureCrypter to prepare a host for Mallox ransomware. They blind Windows Defender with exclusion commands, establish persistence via user-profile Run keys, and retrieve encrypted stages disguised as common media files like .mp4 or .pdf.

### How the hunt flows

The first phase queries process activity for Add-MpPreference commands or specific Mallox binary names. This identifies hosts where the adversary is actively weakening local security to prevent the detection of subsequent payloads.

The hunt then pivots in parallel to registry and network surfaces. It looks for rare registry Run keys pointing to executables in AppData or Public folders, which PureCrypter uses for persistence. Simultaneously, it examines HTTP traffic for downloads of media-themed files that are actually encrypted stages. This phase relies on frequency analysis to filter out legitimate software updates and common web traffic.

Finally, an agent correlates these three signals. It checks if the Defender exclusions, the persistence mechanisms, and the suspicious downloads occur on the same host within a tight timeframe. This correlation helps distinguish administrative tasks from an active ransomware infection chain.

### What the hunt cannot see

The hunt cannot see activity on hosts without EDR coverage. If the loader successfully patches AMSI or ETW, script-based logging may fail, leaving only process command-line evidence. Additionally, because the downloaded media files are encrypted with 3DES, network inspection cannot confirm their contents without endpoint behavioral context.

### How to run it

This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries and automated triage steps. It targets Windows servers, specifically those running Microsoft SQL Server.
