# Hunting Cron Persistence in the Data Tier

### Why Now

Persistence works best where nobody is looking. The independent researcher @TheM3gatr0n reports, in a post we have not verified (https://x.com/TheM3gatr0n/status/2110405943964090564), finding a crontab entry inside a Redis pod on a multi-tenant SaaS platform: `*/5 * * * * /bin/sh /data/pwn.sh`, a netcat reverse shell. The post attributes it to the operator of an autonomous, LLM-driven attack platform.

Writing cron through Redis is not new. Datadog documented RedisRaider in May 2025 pointing Redis at `/etc/cron.d` and saving a cron payload. Worms like P2PInfect have gone after exposed Redis for years.

Containers add a twist. Unit 42 notes the cron technique does not work in containers, and stock Redis images ship without a cron daemon, so the entry in that pod may never have fired. That is worth knowing in its own right. An automated attacker tries things whether or not they work, and the attempts stay on disk. On a VM or a node with cron running, the same entry calls home every five minutes.

### The Hypothesis

An attacker has planted a cron entry in a data-tier container or host, such as one running Redis. The entry runs a script from a writable data or temp directory every few minutes and opens a reverse shell to an external address.

### How the Hunt Flows

The hunt first lists hosts running Redis, Valkey or KeyDB, and checks the external attack surface for datastore ports answering on the internet.

Six checks then run in parallel, and most of them ask the host about its current state rather than waiting for an event.

- **Datastore writes.** Has redis-server or a compatible process written into a cron directory, an `authorized_keys` file or a `.sh` script? A healthy datastore writes only its own dump and append files.
- **Cron from writable paths.** Read the crontabs and list entries that run something from `/data`, `/tmp` or `/dev/shm`, pipe a download into a shell, or use `/dev/tcp`.
- **Rare cron commands.** Rank every cron command by how many hosts run it. A planted job usually appears on one or two.
- **Cron runs in syslog.** Where cron logs reach syslog, count how often scripts from writable paths ran and across how many hours.
- **Reverse shells.** Find netcat, socat or a shell started by cron, or with arguments that wire a socket to a shell.
- **Timer callbacks.** Find shell tools calling the same public address in six or more different hours. That is a schedule, not a person.

A hunt agent combines these per host. A cron entry from a writable path plus a recurring outbound connection from a shell tool is malicious. Either one alone is suspicious. Containment and credential rotation follow with an analyst's approval.

### What the Hunt Cannot See

- **Redis commands.** Redis keeps no command audit trail by default, so the `CONFIG SET` that wrote the file has no client address attached.
- **Pods without agents.** A pod with no agent, or one that has already been rescheduled, reports nothing. Only egress from the node remains.
- **The pod environment.** The researcher says the pod's environment named internal services for about 20 tenants. Reading environment variables leaves no host trace, and without the pod spec the blast radius cannot be stated.

### How to Run This Hunt

The hunt is an open hunt.md playbook. It imports into Huntbase or any hunt.md-aware runtime. It reads standard inventory, scheduled job, file, process, syslog and network surfaces. Run it fleet-wide, not only on datastore hosts, because the technique is not specific to Redis. Promote the writable-path cron check and the datastore-write check to standing detections.
