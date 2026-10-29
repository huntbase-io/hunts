# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/huntbase-io/hunts/security/advisories/new)
("Report a vulnerability" on the repository's **Security** tab). Do not open a
public issue or pull request for a suspected vulnerability.

Include the hunt's slug or the file path, what you found, and how it could be
misused. We will acknowledge your report within 5 working days, keep you
updated while we look into it, and credit you in the advisory unless you
prefer otherwise.

## Scope

This repository holds published threat hunts: `hunt.md` files, Huntbase
playbook definitions, write-ups and metadata. The `gh-pages` branch holds the
built site served at hub.huntbase.io. In scope are, for example:

- a hunt whose queries or steps would change, delete or exfiltrate data when
  run, rather than only read telemetry;
- a published file that contains credentials, personal data, or material that
  should not be public under its source's TLP marking;
- links in a hunt or write-up that lead to malicious content;
- script injection or similar issues in the site built from this repository.

Wrong or noisy detection logic is not a vulnerability. Open an
[issue](https://github.com/huntbase-io/hunts/issues/new) with the hunt's slug
instead.

Issues in the research a hunt is based on belong with its original authors.
Issues in the hunt.md format or its tooling belong in
[hunt-md](https://github.com/huntbase-io/hunt-md/security/advisories/new).

## Using hunts safely

Hunts are machine-drafted and reviewed by a person, but they are starting
points, not guarantees. Read a hunt's queries before you run it, run it with
read-only credentials where you can, and check the parameters and blind spots
against your own environment.
