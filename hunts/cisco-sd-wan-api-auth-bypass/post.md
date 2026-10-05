# Hunting for Cisco SD-WAN Manager API Authentication Bypass (CVE-2026-76504)

### Why now

Rapid7 recently detailed active exploitation of a critical authentication bypass in Cisco Catalyst SD-WAN Manager, tracked as [CVE-2026-76504](https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-sd-wan-manager-api-authentication-bypass-exploited-in-the-wild-cve-2026-76504). This vulnerability allows an unauthenticated attacker to gain administrative access by submitting a specially crafted HTTP request to the management API. Because this appliance often sits at the edge of a corporate network, a compromise provides a direct path to intercepting or redirecting enterprise traffic.

### The Hypothesis

An attacker is bypassing authentication on an internet-exposed Cisco Catalyst SD-WAN Manager by using URL-encoded characters in the j_security_check path, gaining administrative access through reserved system accounts.

### How the hunt flows

The hunt begins at the network perimeter. The lead query inspects the `hb_http_activity` surface for HTTP POST requests directed at the authentication endpoint. It specifically looks for URL-encoded characters, such as %6a, within the path. While many security products may alert on this pattern, the hunt treats this only as a lead to be validated against the environment's specific appliance footprint.

If the lead query returns results, the hunt enters an evaluation phase. An analyst or agent confirms if the URI pattern represents a bypass attempt. This step gates the more expensive follow-on queries to ensure the team only triages hosts that show genuine signs of targeting.

Once a potential bypass is confirmed, the hunt fans out into three parallel investigations. First, it queries `hb_software_inventory` to determine if the targeted host runs a vulnerable version of Cisco SD-WAN Manager (such as 20.9, 20.12, or 26.1). Second, it stack-counts the suspicious URI across the entire fleet to identify if the activity is a rare outlier. Third, it checks `hb_auth_signin` for logins from reserved system accounts, specifically those starting with the "viptela-reserved-" prefix, which are often hijacked during successful exploitation.

In the final phase, an agent correlates the URI bypass, the software version, and the account activity. If a vulnerable host shows both the bypass attempt and a subsequent reserved account login, the hunt triggers an isolation action. This restricts network access to the compromised appliance while an analyst begins a manual forensic review of on-device logs.

### What this hunt cannot see

This hunt has two primary blind spots. First, it relies on HTTP logs having sufficient detail to see the raw URL path. If an attacker uses multiple layers of encoding or the logging system performs aggressive normalization before the hunt can inspect the string, the lead query may miss the bypass attempt. Second, SD-WAN appliances are typically closed systems. The hunt can see the management API and the authentication logs provided to the central log server, but it cannot see local command execution or binary persistence unless those actions generate external log events.

### How to run it

This hunt is provided as a `hunt.md` playbook. You can import it into any hunt.md-aware runtime or the Huntbase platform. The playbook includes the necessary SQLite queries for HTTP, software inventory, and authentication surfaces. Users should set the `lookback_days` parameter based on their log retention to capture the initial exploitation window.
