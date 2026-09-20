# CHAINDROP: Hunting for npm Supply Chain Worms on Developer Endpoints

### Why we are hunting for CHAINDROP

Elastic Security Labs recently published a report titled [Shai-Hulud strikes again: CHAINDROP worm hits 400+ npm packages](https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain). The research details a supply chain campaign that trojanizes popular npm packages to execute malicious hooks during installation. Because these packages often sit on developer workstations or build servers, the adversary gains direct access to high-value credentials and source code. We designed this hunt to find the endpoint footprint of this worm before it propagates or exfiltrates sensitive tokens.

### The Hypothesis

An attacker gains initial access through a backdoored npm package preinstall hook. This hook executes a dropper to install a rogue Bun runtime and harvest developer credentials from local IDE configurations like VS Code or Claude settings. The adversary uses the legitimate-looking Bun binary to perform local discovery and exfiltration while remaining hidden from traditional Node.js process monitors.

### How the Hunt Flows

The hunt starts by narrowing the field. The first query searches the host software inventory for specific packages identified in the CHAINDROP campaign, such as `keyv`, `flat-cache`, and `cache-manager`. This scoping step avoids scanning the entire fleet for behavioral anomalies, which reduces noise and resource consumption.

Once the hunt identifies a host with a suspicious package, it moves into a behavioral fan-out phase. One path looks for the execution of the primary dropper and its payloads, specifically checking process command lines for filenames like `setup.mjs`, `math_symbol.js`, or `math_init.js`. These files are key indicators of the worm's second-stage execution.

Simultaneously, the hunt performs a prevalence check on the Bun runtime. Since many development environments do not use Bun, its presence on a small number of hosts is an anomaly. The query stacks Bun executions by path and command line across the fleet. It highlights instances where Bun runs from temporary or unusual directories, a common tactic for the CHAINDROP payload.

In the final phase, an analyst or automated agent synthesizes these signals. An infected verdict requires the presence of the compromised package correlated with either the dropper execution or a rare Bun runtime event. If confirmed, the hunt provides instructions to isolate the host and revoke associated cloud and repository tokens.

### What this Hunt Cannot See

Software inventory queries rely on point-in-time snapshots. If an adversary installs a compromised package and removes it immediately after the preinstall hook runs, the inventory query might miss it. Additionally, if the infection occurred several weeks ago, endpoint process logs might have rolled over, leaving only the software inventory as evidence of the initial compromise.

### How to Run this Hunt

This hunt is available as an open `hunt.md` playbook. It uses a gated logic that only triggers deeper queries if initial leads exist. You can import this playbook into Huntbase or any runtime that supports the `hunt.md` standard. The design ensures you only run expensive behavioral queries on the hosts that actually need them.
