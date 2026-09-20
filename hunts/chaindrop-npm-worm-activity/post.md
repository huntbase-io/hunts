# Hunting ChainDrop: Detecting NPM Worms and CI Memory Scraping

### Background and Source

Recent research by Unit 42 titled ChainDrop: Inside a Self-Propagating npm Worm (https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/) details a sophisticated threat targeting the JavaScript ecosystem. The worm spreads by trojanizing common npm packages and hijacking the preinstall lifecycle hook. It uses the Bun runtime to execute its dropper, allowing it to bypass some standard Node.js instrumentation and monitoring. 

### Hypothesis

An intruder infects an npm package and triggers a preinstall hook. This hook uses the Bun runtime to harvest credentials from the local filesystem and scrape GitHub Actions runner process memory for OIDC tokens and secrets.

### How the Hunt Flows

The hunt begins with a scoping phase. A query scans the software inventory for hostnames running specific trojanized npm packages, such as keyv or cacheable-request. This establishes a baseline of potentially affected hosts but does not confirm infection on its own.

Next, the hunt looks for execution evidence in two parallel paths. The first path searches process activity for command lines referencing the setup.mjs dropper or internal state variables used to prevent recursion. The second path identifies rare instances of the Bun runtime. Because Bun is less common than Node.js in many enterprise environments, stack-counting its execution helps find the worm's beachhead on workstations or runners.

After identifying execution, the hunt pivots to assess impact. It examines file activity to find instances where Node or Bun processes access sensitive files like .env, .npmrc, or SSH keys. For CI environments, the hunt looks for command lines that indicate the worm is reading the Linux proc filesystem specifically to scrape memory from the GitHub Actions worker process.

Finally, the hunt provides a triage step where an analyst confirms the chain from the infected package to the final credential harvest. If confirmed, the playbook includes an action to isolate the host and remediate specific files in the .claude or .vscode directories.

### Blind Spots

Short-lived CI runners pose the highest risk to this hunt. If the worm executes on a runner that is destroyed before its process and file logs are shipped to a central sink, the hunt will not see the activity. Additionally, the detection of memory scraping relies on the presence of specific procfs strings in command-line arguments. If the adversary uses a compiled binary that interacts with memory directly without shell helpers, this signal disappears.

### How to Run This Hunt

This hunt is provided as a hunt.md playbook. It is a portable, structured format that can be imported into the Huntbase runtime or any hunt.md-aware tool. The playbook automates the pivots between inventory and behavior, allowing teams to run this as a periodic check or a rapid response to new supply chain disclosures.
