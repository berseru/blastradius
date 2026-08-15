# blastradius

Answer one question fast, and answer it with evidence:

> A package was just found malicious. **Which of my services are exposed, through
> which dependency chain, and were they exposed at the moment it mattered?**

Built for Hack Hydra (Track 2 — repos, dependencies and code as graphs) on
[HydraDB](https://github.com/hydra-db/hydradb).

## Why this exists

Every dependency scanner ends its report the same way: *upgrade to the fixed
version*. For the npm ecosystem that advice is now mostly fiction.

Numbers from the OSV npm dump, counted by this project's own parser. CI re-derives
them on every run into `artifacts/corpus.json`; these are from the run of
2026-08-15, covering advisories published between 2017-10-24 and 2026-08-14:

| | count | share |
|---|---|---|
| advisories in the dump | 226,833 | 100% |
| `MAL-*` malicious-package records | 219,676 | 96.8% |
| ...of those, ones offering a fixed version | **26** | 0.01% |
| `GHSA-*` vulnerabilities | 7,157 | 3.2% |
| ...of those, ones with no fix available | 1,659 | 23% |

OSV publishes new malicious-package records daily — the day before this run the
same command counted 226,798 — so the totals move. That is why `blastradius
stats` is in the repo and runs in CI, rather than a number being pasted into this
file and quietly going stale.

When a package is malicious there is nothing to upgrade to. The only useful
questions are *what did it reach*, *how*, and *for how long* — and those are
graph questions, not table questions.

So `blastradius` does not produce a list of findings. It answers reachability:

- **Blast radius** — every service reachable from a compromised package, and the
  actual dependency chain that connects them, hop by hop.
- **Choke points** — the packages that, if compromised, would reach the most
  services. Where to spend attention *before* an incident.
- **Maintainer reach** — one account, not one package: if that account were
  taken over, how far does it get? Account takeover is how supply-chain attacks
  start.
- **Exposure window** — the days between a version being published and an
  advisory naming it. Whether you were exposed *when it mattered*, not just now.

## The graph

Six node kinds, six edge kinds. Deliberately small, because every edge has to
carry weight in a traversal:

```
(Svc)  -[:USES {direct, dev}]->      (Ver)
(Ver)  -[:DEPENDS {requirement}]->   (Ver)
(Ver)  -[:OF]->                      (Pkg)
(Maint)-[:MAINTAINS]->               (Pkg)
(Adv)  -[:AFFECTS {introduced, fixed}]-> (Ver)
(Pkg)  -[:SIMILAR {distance, downloads_ratio}]-> (Pkg)
```

`DEPENDS` is built from the lockfile that was submitted, resolved the way npm
resolves it — nearest enclosing `node_modules` first, then a unique name, then
the semver range. It is deliberately *not* re-resolved against the registry:
today's release of a package has today's dependencies, while the lockfile pins
what shipped. Resolving live gives edges that hang off versions nobody installed,
which is a graph of a codebase that does not exist.

`SIMILAR` is the typosquat layer: names one edit apart (Damerau-Levenshtein,
including transpositions), kept only when the popular side clears 10,000 weekly
downloads and the suspect side is under 1% of it. Both the distance and the
download ratio ride on the edge, so "impersonation" is a measured claim rather
than a hunch. It is what lets the graph explain *how* malware entered a tree,
rather than only that it is present.

## Quickstart

Requires Docker and Python 3.11+.

**1. Start HydraDB** (single node, local object store):

```bash
mkdir -p /tmp/hydra/store /tmp/hydra/cache
printf 'local-development-token-32-bytes' > /tmp/hydra/token   # 32 characters, see below

docker run -d --name hydradb \
  --user "$(id -u):$(id -g)" \
  -p 7687:7687 -p 8443:8443 -p 9090:9090 \
  -v /tmp/hydra:/data \
  -e CLOUD_PROVIDER=local -e LOCAL_PATH=/data/store \
  -e GRAPH_NAMESPACE=default -e GRAPH_ID=default \
  -e GRAPH_CELL_ID=cell-0 -e GRAPH_CELLS=cell-0 \
  -e GRAPH_NODE_ID=node-0 \
  -e GRAPH_BOLT_NODE_ADDRESSES=node-0=127.0.0.1:7687 \
  -e GRAPH_ADVERTISED_BOLT_ADDR=127.0.0.1:7687 \
  -e GRAPH_DATA_CACHE_DIR=/data/cache \
  -e GRAPH_AUTH_TOKEN_FILE=/data/token \
  -e GRAPH_ALLOW_PLAINTEXT=true \
  -e RUST_MIN_STACK=33554432 \
  ghcr.io/hydra-db/hydradb:0.1.1
```

The token is not decoration and its length is not arbitrary: HydraDB reads it
with `read_auth_token`, which refuses anything under 32 characters or equal to
`change-me`, and the process exits about two seconds after `docker run` has
already printed a container id. The only symptom is a port that never opens, so
`blastradius wait` checks the length before it waits and tells you to read
`docker logs hydradb` if the port stays shut.

`RUST_MIN_STACK` is not optional — the query engine recurses deeply enough to
overflow the default thread stack on real dependency graphs.

**2. Install and point it at the node:**

```bash
pip install -e .

export HYDRA_URL=http://127.0.0.1:8443
export HYDRA_ADMIN_URL=http://127.0.0.1:9090
export HYDRA_TOKEN=local-development-token-32-bytes
```

**3. Ingest and ask:**

```bash
blastradius wait                      # block until a query round-trips
blastradius selftest                  # every statement, on 11 synthetic vertices
blastradius contract                  # the failure paths: 401, wrong graph, writes that landed
blastradius ingest --seeds 40         # registry + OSV -> graph
blastradius verify --out artifacts/results.json
blastradius serve --selfcheck --dump-dir artifacts/api-samples   # drives every route
blastradius crosscheck                # those answers vs the live OSV API
blastradius incident axioss           # a package was just called malicious: the six answers
blastradius ask typosquat-incident
blastradius stats                     # ecosystem counts, no database needed
```

`selftest` takes a couple of seconds and is worth running first: it writes a
miniature graph with the production statements, runs every production query
against it, checks the answers and deletes it again, reporting each statement the
server refuses with the server's own message. It is how an unsupported query gets
found before a 219 MB download rather than after it.

`crosscheck` reads the answers `serve --selfcheck` dumped, which is why that
line comes first: it re-asks the live OSV API about a sample of them, so the run
is checked against a source that is not this project's own parser.

`ingest` downloads the OSV npm archive once (~219 MB) into `data/` and caches
every registry response under `data/cache/`, so re-runs are cheap and offline.

**4. Open the UI:**

```bash
blastradius serve                     # http://127.0.0.1:8080
```

![the service view](docs/screenshots/service-view.png)

Every screenshot in `docs/screenshots/` is the real page rendered against
`artifacts/api-samples/` from a CI run — the same 2,278-package graph the numbers
below come from, not a mock-up. `serve --selfcheck --dump-dir` writes those
payloads, since CI is the only place a populated graph exists.

Four views over the same graph, no build step and no extra dependency — the API
is `http.server`, the page is one HTML file:

- **service** — hits, how deep they sit, choke points, exposure windows, the
  lookalike names it ships, and every chain. Each hop in a chain is clickable.
- **package** — "this was just called malicious": which services it reaches and
  through which chains, who can publish it, what it impersonates.
- **maintainer** — if this npm account were taken over, what does it touch?
- **lookalikes** — every `SIMILAR` edge with both download counts, so a
  detection can be argued with instead of trusted.

Search is a prefix query against the graph (`WHERE name STARTS WITH`), not a
filter in Python.

| ![package view](docs/screenshots/package-view.png) | ![lookalike view](docs/screenshots/lookalikes-view.png) |
|---|---|
| `axioss` — malicious, no fix, one npm account away | every lookalike pair with both download counts |

```bash
blastradius serve --selfcheck         # drive every route once, then exit
```

`--selfcheck` is what CI runs: it binds an ephemeral port, calls every route over
real HTTP and asserts on content — a service with zero hits, a page with no
chains or an empty search all fail the build. A route that returns `200 {}` is the
failure mode worth catching.

## How HydraDB is used

The point of the project is that the interesting questions are traversals, so
they are pushed into the database rather than pulled into Python.

- **`algo.MSpaths` for blast radius.** One call returns the ranked paths from a
  compromised package to every service that reaches it, with the intermediate
  hops intact — the chain *is* the answer, so a reachability boolean would not
  do. Endpoints are selected by string property (`Pkg.name`, `Maint.login`,
  `Adv.osv`), which is what the procedure's vertex-property index supports.
- **Cypher for the rest.** Direct hits, depth profile, choke points, maintainer
  footprint and exposure windows are aggregations over the same graph.
- **Search as a query, not a scan.** A pattern can carry an inline non-id
  property and `WHERE` supports `STARTS WITH` (but not `CONTAINS` or `IN`), so
  package and maintainer prefix search happen in the database, with `LIMIT` taken
  as a parameter.
- **Bulk writes via `UNWIND $rows`.** Ingest sends nested-JSON parameter batches
  over the HTTP query endpoint, upserting with `MERGE` by id then `SET`, vertices
  before edges. Batches are the only multi-row write there is: outside an
  `UNWIND`, a `MERGE` cannot be followed by any clause at all, so every statement
  in `model.py` is a batch. Chunks are bounded by row count *and* by serialised
  size, because the server caps a request body at 1 MiB.
- **Stable 62-bit ids** (blake2b, 4-bit kind tag per label) so an ingest is
  idempotent and re-runnable without duplicating nodes.
- **Cursor-aware reads.** The client follows `next_cursor` so result sets larger
  than one page are complete rather than silently truncated.

Written against the server's own source, not against assumptions: variable-length
hop bounds are formatted as range-checked integer literals because the parser
resolves them against an empty parameter map, and the traversal ceiling matches
the server default of 16 hops.

Two other rules shaped the schema, both enforced by the server rather than by
convention. A vertex upsert has to `MERGE` on `id` alone — folding properties
into the pattern is rejected, since the pattern is the identity being matched.
And there is no null property value: a `None` anywhere in a parameter fails the
whole request, so "we do not know when this was published" is written as the
sentinel `0` and read back as unknown (`queries.known_time`), never as 1970.

## The six questions, answered

The track states the questions a defender has to answer when a package is
compromised. `blastradius incident <package>` answers all six from the same
graph, reading it from the compromised name outwards - the direction the
question actually arrives in, and the opposite of every other command here:

```
$ blastradius incident axioss
```

| # | The question | Where the answer comes from |
|---|---|---|
| 1 | Which internal services are transitively exposed? | the `USES` edges to that exact pinned version — a lockfile is the fully resolved tree, so this cannot miss a service — plus the shortest chain up to a dependency the service actually chose, which is *how far away* it is |
| 2 | Which version of the dependency introduced the vulnerability? | the `introduced`/`fixed` boundaries carried on the `AFFECTS` edge, with the publication date of the first affected release |
| 3 | Which applications resolved the compromised version while it was live? | each lockfile's own snapshot date against the window between the bad release and its fix |
| 4 | Which other packages share maintainers or infrastructure with it? | `MAINTAINS`, in one traversal - a relationship that does not exist in a lockfile at all |
| 5 | Are there likely typosquat packages nearby? | `SIMILAR`, read in both directions: this name impersonating another, and others impersonating it |
| 6 | What is the complete blast radius? | every chain from a bad version to something deployed, via the native path procedures |

Each answer records the statements it ran and how long they took, and the whole
report is written to `artifacts/incident-*.json` by CI, so "this takes seconds"
is a measurement rather than a claim.

Question 1 is also where the dialect had to be taken seriously. Walking
*dependents* upwards — `(bad)<-[:DEPENDS*1..6]-(entry)` — reads naturally and is
refused outright: a variable-length `MATCH` is planned from the arrow source, and
the server needs a fixed vertex id there (`variable-length MATCH requires a fixed
source id`). Reading against the arrow is what the native path procedures are
for, so the chains come from `algo.MSpaths` with `relDirection: 'incoming'`, and
a pinned version that no chain explains inside the hop limit is reported as
exactly that rather than being quietly called a direct dependency.

Question 3 is the one that needs a graph with time in it. A lockfile carries no
date, so the snapshot date comes from the commit that last touched the file (the
examples state it explicitly, which is why they disagree with each other). That
turns three different situations into three different answers instead of one:

- the snapshot predates the bad release — **not exposed**, whatever the scanner says today;
- the snapshot sits inside the window, before disclosure — **shipping it while nobody knew**;
- the snapshot is after a fixed version existed — **exposed, but it was avoidable**.

A name the graph has never seen exits non-zero and says so. "We have no data
about this package" and "you are not affected" are different answers, and during
an incident the difference is the whole job.

## Example services

Four lockfiles under `examples/`, resolved from the real npm registry:

| service | lockfile entries | distinct pins | what it demonstrates |
|---|---|---|---|
| `checkout-api` | 249 | 248 | an ordinary API a year behind on upgrades |
| `admin-dashboard` | 488 | 484 | a large front-end tree, mostly dev dependencies |
| `data-worker` | 47 | 47 | a small tree with critical database vulnerabilities |
| `typosquat-incident` | 82 | 82 | five real malicious typosquats, none with a fix |

The two columns differ because npm writes the same `name@version` at more than one
path in `node_modules`, and a graph node is the version, not the path: 866
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

## What a run actually returns

Every number below was read out of `artifacts/results.json` and
`artifacts/ingest.json` of one CI run (2026-08-15, commit `de6f532`), not
written by hand. The advisory counts move every day, because OSV publishes new
malicious-package records daily; the graph counts do not, because the seeds are
pinned. 134 seed packages expand into the graph the
four example services are measured against:

| | count |
|---|---|
| packages / versions | 2,278 / 2,990 |
| maintainer accounts | 1,036 |
| advisories kept (of 226,833 scanned) | 130 |
| `DEPENDS` / `USES` / `MAINTAINS` edges | 6,418 / 861 / 5,280 |
| `AFFECTS` / `SIMILAR` edges | 180 / 5 |

Per service — pinned versions an advisory names, how many of those are malware,
how many have no fixed version at all, and how many distinct dependency chains
lead to them:

| service | hits | malicious | unfixable | chains | worst exposure (days) |
|---|---|---|---|---|---|
| `checkout-api` | 61 | 0 | 0 | 16 | 2,853.5 |
| `admin-dashboard` | 46 | 0 | 1 | 12 | 2,322.9 |
| `data-worker` | 36 | 0 | 0 | 3 | 2,159.6 |
| `typosquat-incident` | 20 | 5 | 7 | 8 | 2,167.5 |

The chains are the product, so here are three verbatim:

```
elliptic@6.6.1 -> browserify-sign@4.2.6 -> crypto-browserify@3.12.1 -> node-libs-browser@2.2.1 -> webpack@4.43.0
minimist@1.2.0 -> mkdirp@0.5.6 -> tar@4.4.10
follow-redirects@1.15.11 -> axios@0.21.1
```

Choke points rank by how many paths run through them, which is why they are
worth pre-emptive attention: `es-errors@1.3.0` carries 71 paths in
`checkout-api`, `inherits@2.0.4` 53 in `admin-dashboard` — small packages nobody
chose, sitting under everything.

Typosquat detection on the same run produced five `SIMILAR` edges over 2,278
packages - the five real malicious names, and nothing else - with the popularity
gap it measured:

| suspect | weekly downloads | impersonates | weekly downloads | ratio |
|---|---|---|---|---|
| `axioss` | 33 | `axios` | 119,805,667 | 2.8e-07 |
| `chalkk` | 3 | `chalk` | 490,712,867 | 6.1e-09 |
| `comander` | 10 | `commander` | 476,596,961 | 2.1e-08 |
| `expess` | 138 | `express` | 127,296,948 | 1.1e-06 |
| `fodash` | 5 | `lodash` | 167,905,798 | 3.0e-08 |

Getting there took removing a false positive the detector used to produce. An
earlier run reported `color -> colord` and `synckit -> asynckit`, because OSV
names `color` and `synckit` in malicious-release advisories and "already known to
be malware" used to waive the popularity check. Both are among the most installed
packages on npm; being compromised is not impersonating, and the compromise is
already reported through the advisory edge. The waiver now covers only missing
download data, and both pairs are pinned as a regression test. This is also why
every run lists its pairs with both download counts in `artifacts/ingest.json`
rather than only counting them - a detection nobody can check is a detection
nobody should trust.

Query latency on that graph, worst case across the four services in that run —
these move with whatever else the shared CI runner is doing, so treat them as an
order of magnitude, not a benchmark: depth profile 3,163 ms, choke points
1,119 ms, lookalikes 488 ms, blast-radius paths 108 ms, direct hits 184 ms,
exposure windows 100 ms. Ingest wrote 22,172 rows in 7.4 s; the
226,833-advisory dump was parsed in 12.5 s; `selftest` put all 25 checks against
a live node in 0.16 s, `contract` ran its 14 checks in 7.1 s, `crosscheck`
re-asked the live OSV API about 24 findings and agreed on 24, and
`serve --selfcheck` drove all 23 API checks over HTTP against the same graph.

## Reproducing the numbers

Nothing in this README is hand-counted. `blastradius verify` runs every query
against a live node and writes `artifacts/results.json`; CI publishes that file
as a build artifact on every push, alongside the container logs of the HydraDB
node it ran against. The ecosystem counts above come from `blastradius stats`, which
parses the dump in ~13s and writes `artifacts/corpus.json`.

## Tests

```bash
pip install -e ".[dev]"
pytest tests/unit -q
```

The unit suite covers the parts where being quietly wrong would be invisible:
semver range matching (including prerelease rules), OSV timestamp parsing,
lockfile v1/v2/v3 shapes, id collision safety, advisory de-duplication and row
building. `tests/unit/test_statements.py` additionally holds every statement to
the rules the database enforces — batch form, `MERGE` on `id` alone, no nulls,
every field present in every row, body-size-bounded chunks — so a violation fails
in 0.2s locally instead of minutes into a CI run.

Every command shown in this README is executed by CI, including the two that
only print for humans (`ask`, `stats`) — a documented command that nothing runs
is a documented command that quietly rots.

CI runs the suite, then starts a real HydraDB node and runs `selftest`,
`contract`, the ingest, the traversals and the API self-check against it,
publishing `artifacts/selftest.json`, `artifacts/contract.json`,
`artifacts/ingest.json`, `artifacts/results.json`, `artifacts/api.json`,
`artifacts/osv-crosscheck.json` and the node's own logs.

`tests/unit/test_web.py` covers the API without a database, including a test that
the CI self-check *fails* on a graph with no hits — a check that cannot fail is
not a check. The same rule is applied to this project's own checks:
`tests/unit/test_cli_errors.py` points the contract run at a dead port and
asserts that *every* check fails, because a body-cap check that accepts any
transport error passes against nothing at all.

### What happens when a source is unreachable

The registry answers `429` when it is asked too much, and the fetcher retries
with a backoff — the server's own `Retry-After` when it sends one. When the
retries run out the package is missing from the graph — and with it, its
versions, its dependencies and its maintainers, which makes every chain that
would have crossed it disappear. A blast radius that is too small reads as
safety, so this is not a warning:

```
$ blastradius ingest --seeds 40
  3 fetches failed, e.g. ['https://registry.npmjs.org/left-pad (HTTP 429 after 4 attempts)']
3 source fetches failed (allowed: 0); the graph is incomplete
$ echo $?
1
```

`--max-fetch-failures` raises that budget deliberately, in the open. The count
and examples are written into `artifacts/ingest.json` either way.

Not every missing document is that serious, though, and treating them all alike
failed a real run. npm's download counter cannot be asked about scoped names in
bulk, so a cold run asks it once per `@scope/name` — hundreds of times — and a
shared CI address gets rate limited part way through. Failing an entire ingest
because a popularity number for `@babel/plugin-transform-object-super` was
throttled is the wrong trade, so counts are split by what depends on them:

* the two sides of every name pair the lookalike test will weigh are
  **required** — a missing count there changes an answer, so it fails the run;
* every other count is a column in a table. It is fetched, and if it is
  throttled anyway the run continues with that package's popularity recorded as
  unknown (`-1`, never `0`) and the gap reported as `downloads_unknown` in
  `artifacts/ingest.json` and on stdout.

The pace is negotiated rather than guessed: requests to the counter go one at a
time, each `429` widens the gap for every request behind it (up to two seconds),
and each success narrows it again, so a run settles at whatever rate the server
is willing to serve today.

The OSV snapshot is treated the same way: `ingest` and `stats` print how old the
cached archive is and say so loudly past a week, because OSV publishes new
malicious-package records daily and an old snapshot under-reports without ever
looking wrong.

### The failure paths, proved

Happy-path green says very little. `blastradius contract` runs against the live
node in CI and asserts the ways this could be quietly wrong:

| Check | What would be wrong without it |
|---|---|
| `auth_wrong_token`, `auth_empty_token`, `auth_no_header` | the graph answering an unauthenticated caller |
| `auth_valid_token` | a 401 above that really meant "the server is down" |
| `graph_unknown`, `namespace_unknown`, `cell_unknown` | the wrong graph answering `200` with zero rows, which on this UI reads as *"your services are clean"* |
| `write_is_readable` | `200 OK` on a batch the graph never stored — 2,500 rows are written, then counted back out of the graph |
| `rewrite_is_idempotent` | the same batch twice doubling the graph |
| `update_is_visible` | `SET` being accepted without changing stored state |
| `rejected_write_is_not_partial` | a refused batch leaving half its rows behind |
| `server_error_surfaces`, `oversized_row_is_reported` | an error losing its code on the way up, or the 1 MiB body cap silently truncating — the body-cap check first proves the node is reachable, so a refused connection cannot stand in for a refused row |

Running it against HydraDB 0.1.1 found one deviation worth reporting: a query
sent to a **cell that does not exist answers `500`**, where an unknown graph or
namespace answers `403`. It is recorded in the artifact rather than hidden, and
it does not fail the build — the clause that matters, "a wrong address must not
be answered as if the graph were empty", holds either way.

The receipt is `artifacts/contract.json`, with the status code and error code the
server actually returned for each one.

The API has the same treatment: an unknown service, package or maintainer is
`404` and never an empty page, a malformed `limit` is the caller's `400` and not
the server's `500`, and `POST`/`PUT`/`PATCH`/`DELETE` are refused with `405`, so
"read-only" is enforced by the server rather than asserted in this file.

### Checked against a different source

Everything in the pipeline reads one OSV snapshot through one parser, so a
parsing mistake would be invisible: every test would agree with the code that
made it. `blastradius crosscheck` samples the hits this run produced and asks
`api.osv.dev` about each advisory directly, comparing five things — that OSV
agrees the exact version is affected, the disclosure date, the severity, whether
a fix exists, and malware vs vulnerability. The semver comparison it uses is
written from scratch in `crosscheck.py` and does not import the pipeline's
`versions` module, because two independent implementations agreeing is evidence
and one module agreeing with itself is not.

The last run checked 24 sampled hits across all four services and OSV agreed with
every one, `artifacts/osv-crosscheck.json`:

```
ok   minimist@1.2.0     GHSA-xvch-5gv4-984h   range [1.0.0, 1.2.6)
ok   ws@7.2.0           GHSA-6fc8-4gx4-v693   range [7.0.0, 7.4.6)
ok   axioss@1.6.2       MAL-2025-15242        range [0, open)
24/24 sampled hits agree on affectedness, disclosure date, severity, fix availability and kind
```

A network failure is reported as unreachable rather than as a disagreement: an
outage at OSV is not evidence that the graph is wrong.

`tests/unit/test_contract.py` then runs those checks against fake servers that
each break one clause on purpose — one that accepts any token, one that answers a
wrong graph with an empty result, one that accepts writes and stores nothing, one
that duplicates rows on rewrite — and requires the matching check to fail. A test
suite that only proves the good case proves nothing.

## Data sources and attribution

- **[OSV](https://osv.dev)** — advisory data, npm dump
  (`osv-vulnerabilities.storage.googleapis.com/npm/all.zip`), CC-BY-4.0.
- **[npm registry](https://registry.npmjs.org)** — package metadata, version
  publication times, maintainer accounts.
- **[deps.dev](https://deps.dev)** — resolved dependency graphs used to build the
  example lockfiles.
- **[npm downloads API](https://api.npmjs.org/downloads/point/last-week)** —
  weekly download counts, the popularity side of the typosquat signal.
- **[HydraDB](https://github.com/hydra-db/hydradb)** — the graph database,
  AGPL-3.0, used unmodified as a container image.

Python dependencies: `httpx` (HTTP), `node-semver` (npm-accurate version range
matching), `pytest` (dev only). No other runtime dependencies.

## Licence

[Apache-2.0](LICENSE).
