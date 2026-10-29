# Contributing to hunts

Thanks for helping to improve the hunts. Corrections are the most useful
contribution: a query that does not run, a wrong technique, a missing or wrong
credit, or a blind spot the hunt does not mention.

## Open an issue, not a pull request

This repository is published from a private review queue. Each publication
replaces the `hunts/` directory and the README, so a change made here directly
is overwritten by the next one. Instead:

1. [Open an issue](https://github.com/huntbase-io/hunts/issues/new) with the
   hunt's slug (its directory name under `hunts/`).
2. Say what is wrong and, where you can, what it should be: the corrected
   query, the right ATT&CK technique, or the source to credit.
3. A reviewer fixes the hunt in the review queue, and the fix appears here at
   the next publication.

Security problems, such as a hunt that would change data when run or a file
that exposes sensitive material, go through [SECURITY.md](SECURITY.md), not a
public issue.

## Checking a hunt locally

Each `hunt.md` follows the [hunt.md format](https://github.com/huntbase-io/hunt-md).
To lint one before you report a problem with it:

```bash
pip install "git+https://github.com/huntbase-io/hunt-md.git#subdirectory=tools"
huntmd validate hunts/<hunt-slug>/hunt.md
```

## Keep issues public-safe

Issues are public. Do not include customer names, internal hostnames, IP
addresses, credentials or query results from your own environment.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

The content of this repository is licensed under
[CC BY 4.0](LICENSE). By contributing a correction you agree that it may be
published under the same licence.
