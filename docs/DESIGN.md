# Design notes

Detail that would slow the README down, kept where it can still be read.

## The graph

`DEPENDS` is built from the lockfile that was submitted, resolved the way npm
resolves it — nearest enclosing `node_modules` first, then a unique name, then
the semver range, and only when the recorded requirement admits that version. It
is deliberately *not* re-resolved against the registry: today's release of a
package has today's dependencies, while the lockfile pins what shipped.
Resolving live gives edges that hang off versions nobody installed, which is a
graph of a codebase that does not exist.

Lockfile v1 has no requirement strings for hoisted entries. Rather than
fabricating a `^{version}` range, an entry is marked `direct_source: manifest`
when `package.json` names it and `direct_source: inferred` when it is only known
from hoisting, so "direct dependency" stays a fact instead of a guess.

`SIMILAR` is the typosquat layer: names one edit apart (Damerau-Levenshtein,
including transpositions), kept only when the popular side clears 10,000 weekly
downloads and the suspect side is under 1% of it. Both the distance and the
download ratio ride on the edge, so "impersonation" is a measured claim rather
than a hunch. It is what lets the graph explain *how* malware entered a tree,
rather than only that it is present.

## Why question 1 needed the dialect taken seriously

Walking *dependents* upwards — `(bad)<-[:DEPENDS*1..6]-(entry)` — reads naturally
and is refused outright: a variable-length `MATCH` is planned from the arrow
source, and the server needs a fixed vertex id there (`variable-length MATCH
requires a fixed source id`). Reading against the arrow is what the native path
procedures are for, so the chains come from `algo.MSpaths` with
`relDirection: 'incoming'`, and a pinned version that no chain explains inside
the hop limit is reported as exactly that rather than being quietly called a
direct dependency.

Two other server-enforced rules shaped the schema. A vertex upsert has to `MERGE`
on `id` alone — folding properties into the pattern is rejected, since the
pattern is the identity being matched. And there is no null property value: a
`None` anywhere in a parameter fails the whole request, so "we do not know when
this was published" is written as the sentinel `0` and read back as unknown
(`queries.known_time`), never as 1970.

## Why question 3 needs time in the graph

A lockfile carries no date, so the snapshot date comes from the commit that last
touched the file (the examples state it explicitly, which is why they disagree
with each other). That turns three different situations into three different
answers instead of one:

- the snapshot predates the bad release — **not exposed**, whatever the scanner says today;
- the snapshot sits inside the window, before disclosure — **shipping it while nobody knew**;
- the snapshot is after a fixed version existed — **exposed, but it was avoidable**.

If the fixed version is not in the graph at all, the window cannot be closed and
the verdict is `unknown: fixed version not in graph` rather than a false
"still exposed".

A name the graph has never seen exits non-zero and says so. "We have no data
about this package" and "you are not affected" are different answers, and during
an incident the difference is the whole job.

## The example services

Four lockfiles under `examples/`, resolved from the real npm registry:

| service | lockfile entries | distinct pins | what it demonstrates |
|---|---|---|---|
| `checkout-api` | 249 | 248 | an ordinary API a year behind on upgrades |
| `admin-dashboard` | 488 | 484 | a large front-end tree, mostly dev dependencies |
| `data-worker` | 47 | 47 | a small tree with critical database vulnerabilities |
| `typosquat-incident` | 82 | 82 | five real malicious typosquats, none with a fix |

The two columns differ because npm writes the same `name@version` at more than
one path in `node_modules`, and a graph node is the version, not the path: 866
lockfile entries become 861 `USES` edges.

They pin deliberately outdated versions, because that is what real applications
look like: the same 25 popular packages pinned to their newest release produce 10
advisories and zero malware, which is a demo that shows nothing.

The typosquat service reproduces the case the tool exists for. The package names
and their `MAL-*` advisories are real OSV records (`expess`, `chalkk`,
`comander`, `fodash`, `axioss`); the malicious *version numbers* are
reconstructed, because npm has already removed those releases — as of 2026-08-14
each of those names resolves to a single `0.0.1-security` placeholder. This is
stated in `scripts/make_example_lockfiles.py` next to the data itself.

## Removing a false positive

An earlier run reported `color -> colord` and `synckit -> asynckit`, because OSV
names `color` and `synckit` in malicious-release advisories and "already known to
be malware" used to waive the popularity check. Both are among the most installed
packages on npm; being compromised is not impersonating, and the compromise is
already reported through the advisory edge. The waiver now covers only missing
download data, and both pairs are pinned as a regression test. This is also why
every run lists its pairs with both download counts in `artifacts/ingest.json`
rather than only counting them — a detection nobody can check is a detection
nobody should trust.
