# Huntbase Hunts

Threat hunts drafted from current public threat research, reviewed by a person,
and published as open [hunt.md](https://github.com/huntbase-io/hunt-md) files.

**Browse them at [hub.huntbase.io](https://hub.huntbase.io).**

Each hunt turns one piece of research into something you can run: a
hypothesis, the queries that test it, what a hit looks like, and what the hunt
cannot see.

## What is in a hunt

```
hunts/<hunt-slug>/
  hunt.md           The hunt in hunt.md format. Run it anywhere that reads the format.
  definition.json   The native Huntbase playbook definition.
  post.md           The write-up that accompanies the hunt.
  meta.yaml         Title, source research, techniques, products, severity and
                    how the hunt was produced.
```

`index.json` at the site root lists every hunt's metadata, and
[`feed.xml`](https://hub.huntbase.io/feed.xml) is an Atom feed of new hunts.

## How hunts are made

1. A pipeline reads public threat research and drafts a hunt for reports that
   describe one real intrusion or technique.
2. Automated gates check the draft: every query is validated against the
   schema of the source it reads, and the hunt.md is linted.
3. A person reviews it. Only approved hunts are published here.

Hunts are machine-drafted and human-reviewed. They are starting points for
your own environment, not guarantees: read the blind spots on each hunt, tune
the parameters, and check the queries against your own telemetry.

## Using a hunt

- **In Huntbase**: open the hunt on the site and choose Run hunt.
- **Anywhere else**: download `hunt.md`. It is a plain Markdown file with a
  YAML header; the queries are SQL over normalized telemetry tables, with the
  columns each one reads listed beside it.

## Found a problem?

Open an issue with the hunt's slug and what is wrong: a query that does not
run, a wrong technique, a missing credit. Corrections are welcome.

## Licence and credit

The hunts, write-ups and metadata are licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The site generator
in `site/` is MIT licensed.

The research each hunt is based on belongs to its original authors, who are
credited and linked on every hunt. The analysis and detection logic are
Huntbase's.

This repository is published from a private review queue. Please do not open
pull requests that add or edit hunts here; open an issue instead.
