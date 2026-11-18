# Hunting the Optimizely Injected Script: Visitors, Sessions and Site Owners

### Why This Hunt Matters

On 16 November 2026 an attacker added JavaScript to Optimizely Web Experimentation projects belonging to 178 organisations, as [BleepingComputer reported](https://www.bleepingcomputer.com/news/security/optimizely-supply-chain-attack-delivers-malware-to-cnn-fox-news-bbc-salesforce-sites/). Scott Helme at [Report URI](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/) found the code in 188 of the 1,611 Optimizely snippets he checked. Because the code sat in each project's own JavaScript, sites such as BBC, CNN, Zoom, GitLab and Salesforce served it from Optimizely's CDN, under Optimizely's certificate, from about 04:21 UTC until clean-up finished at 23:11 UTC.

The script, `track.js` from `1688360.cc`, did four things. It swapped cryptocurrency addresses on the page. From 13:43 UTC it skimmed card numbers, expiry dates and security codes to `/card.php`. After a swap it sent the page URL, readable cookies and a screenshot to `/hit.php`. On iPhones and iPads it loaded the Coruna and DarkSword exploit kits.

The domain is now dead, but that does not settle anything. Anyone on your staff who typed a card, held a wallet page open or was signed in on an affected page during those hours may already have lost data. If your organisation runs Optimizely itself, your own customers may have been the victims.

### The Hypothesis

Staff browsers that visited an affected site on 16 November loaded the attacker's script, and some of them sent card details, readable cookies or iPhone traffic to the attacker. Separately, the organisation's own Optimizely project may have served the script to its customers.

### How the Hunt Flows

The hunt opens with DNS. It lists every managed device that looked up `1688360.cc`, the earlier injector `webshell.lol`, or one of the `.icu` hosts used for the iOS stage. This is the widest list of exposed browsers, and its hosts feed the later steps.

Six queries then run side by side. Proxy logs show who requested the payload host, and the referrer names the site they were on. A second proxy query looks for the data leaving: POSTs to `/card.php` mean a card was submitted, and POSTs to `/hit.php` mean cookies and a screenshot were sent. A third picks out iPhones and iPads that reached the exploit hosts. A connection query on the attacker's last known IP addresses catches browsers that used DNS-over-HTTPS and bypassed the proxy.

Two steps do not depend on the published hosts at all. One finds hosts first seen during the exposure window that browsers fetched scripts or `.php` paths from while on a different site, ranked by how many unrelated sites referred to them and how often an Optimizely snippet was fetched just before. The other stack-counts domains that only the exposed devices looked up for the first time. Both are noisy, because new ad and analytics hosts appear every day, but a rotated host would show up there.

An agent combines this into a table of who loaded the script, who lost a card, who lost cookies and which phones were reached. For those users, the hunt checks sign-ins from addresses they had not used before. A second agent decides whether a session was stolen or reused. Page JavaScript cannot read HttpOnly cookies, so the risk depends on how each site set its cookies.

If theft is likely, the hunt proposes revoking the user's sessions and tokens, gated by approval. It does not isolate laptops: the code ran inside a web page and left nothing on the device. Manual steps follow for card reissue, iPhone version checks, the organisation's own Optimizely projects and crypto transfers to the attacker's wallets.

### What the Hunt Cannot See

Without TLS inspection the proxy logs the host but not the path or method, so a script load cannot be told apart from card theft. Phones on cellular data never reach corporate logs, and those are the devices the exploit kits targeted. Browsers using DNS-over-HTTPS skip the DNS logs. One loader variant ran an embedded copy of the payload when `track.js` could not load, so no script fetch appears. Cookie replay into a SaaS app does not create an identity-provider sign-in, so the sign-in step can be silent while a session is abused. A swapped crypto address leaves no network trace of its own. Changes to your own Optimizely project are only visible in Optimizely. Finally, the logs must still reach back to 9 November.

### How to Run It

The hunt is packaged as a `hunt.md` playbook for Huntbase or any platform that reads the format. Run it over 04:00 UTC 16 November to 06:00 UTC 17 November 2026. The end time includes a few hours' margin for cached snippets and open tabs. Paste the scoping hosts into `scope_hosts` and the triaged users into `scope_users`. If the attacker moves to new hosts, update `payload_domains`, `ios_stage_domains` and `attacker_ips`.

Credit for the primary research goes to Scott Helme and Report URI, with further detail from StepSecurity.
