# ChainDrop: Hunting for Self-Propagating npm Worms and Secret Theft

Recent research by Unit 42, titled [ChainDrop: Inside a Self-Propagating npm Worm](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/), details a worm that infects legitimate packages via preinstall hooks to steal credentials and propagate. Unlike simpler malware, ChainDrop specifically targets developer environments, including VS Code and AI-assisted coding tools, and even scrapes CI runner memory to capture ephemeral OIDC tokens.

Our hypothesis is that an adversary is using these trojanized npm packages to execute background processes that harvest cloud credentials, SSH keys, and CI secrets while establishing cross-linked persistence. This hunt is designed to find these artifacts by connecting the dots between script interpreter behavior and sensitive file access.

The hunt begins by scoping the environment to hosts where Node.js, npm, or Bun are present. This ensures we are looking at the most relevant attack surface without over-processing data from systems that lack the necessary runtimes for the worm to execute.

Next, the flow identifies the execution of specific dropper scripts like `setup.mjs` or `math_init.js`. Since these are often spawned by legitimate interpreters, we focus on the command-line arguments and environment variables that signify the worm's initialization routine rather than just the process names.

The core of the hunt is a three-pronged correlation phase. We look for rare file access where interpreters like `node` or `bun` read sensitive files such as SSH keys or `.env` configurations. Simultaneously, we monitor for the creation of persistence artifacts in IDE directories, specifically targeting VS Code tasks and Claude Code settings. We also examine access to `/proc/mem` and `/proc/maps`, a high-confidence indicator of the worm's attempt to scrape CI runner memory for secrets.

There are two primary blind spots to consider. First, if your telemetry does not capture full command-line arguments for interpreters, the specific script names will be invisible. Second, many EDR platforms filter access to the `/proc` filesystem by default to reduce noise; if this filtering is active, the memory-scraping behavior characteristic of the CI-targeting logic will not be detected.

To run this hunt, you can import the provided `hunt.md` playbook into Huntbase or any compatible runtime. It uses a triage agent to correlate these signals temporally, ensuring that a verdict is only reached when execution and credential theft occur on the same host within a narrow window.
