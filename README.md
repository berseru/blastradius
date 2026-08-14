# blastradius

Answer one question fast, and answer it with evidence:

> A package was just found malicious. **Which of my services are exposed, through
> which dependency chain, and were they exposed at the moment it mattered?**

Built for Hack Hydra (Track 2 — repos, dependencies and code as graphs) on
[HydraDB](https://github.com/hydra-db/hydradb).

## Why this exists

Every dependency scanner ends its report the same way: *upgrade to the fixed
version*. For the npm ecosystem that advice is now mostly fiction.

Numbers from the OSV npm dump of 2026-08-14, counted by this project's own
parser — run `blastradius stats` to re-derive them, no database required:

| | count | share |
|---|---|---|
| advisories in the dump | 226,798 | 100% |
| `MAL-*` malicious-package records | 219,644 | 96.8% |
| ...of those, ones offering a fixed version | **26** | 0.01% |
| `GHSA-*` vulnerabilities | 7,154 | 3.2% |
| ...of those, ones with no fix available | 1,659 | 23% |

OSV publishes new malicious-package records daily, so a run tomorrow returns
slightly larger totals. That is why the command is in the repo rather than the
number being pasted into it.

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
printf 'dev-token' > /tmp/hydra/token

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

`RUST_MIN_STACK` is not optional — the query engine recurses deeply enough to
overflow the default thread stack on real dependency graphs.

**2. Install and point it at the node:**

```bash
pip install -e .

export HYDRA_URL=http://127.0.0.1:8443
export HYDRA_ADMIN_URL=http://127.0.0.1:9090
export HYDRA_TOKEN=dev-token
```

**3. Ingest and ask:**

```bash
blastradius wait                      # block until a query round-trips
blastradius selftest                  # every statement, on 11 synthetic vertices
blastradius ingest --seeds 40         # registry + OSV -> graph
blastradius verify --out artifacts/results.json
blastradius ask typosquat-incident
```

`selftest` takes a couple of seconds and is worth running first: it writes a
miniature graph with the production statements, runs every production query
against it, checks the answers and deletes it again, reporting each statement the
server refuses with the server's own message. It is how an unsupported query gets
found before a 219 MB download rather than after it.

`ingest` downloads the OSV npm archive once (~219 MB) into `data/` and caches
every registry response under `data/cache/`, so re-runs are cheap and offline.

**4. Open the UI:**

```bash
blastradius serve                     # http://127.0.0.1:8080
```

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

Every number below was read out of `artifacts/results.json` from one CI run
(2026-08-14), not written by hand. 134 seed packages expand into the graph the
four example services are measured against:

| | count |
|---|---|
| packages / versions | 2,278 / 2,990 |
| maintainer accounts | 1,036 |
| advisories kept (of 226,817 scanned) | 130 |
| `DEPENDS` / `USES` / `MAINTAINS` edges | 6,418 / 861 / 5,280 |
| `AFFECTS` / `SIMILAR` edges | 180 / 5 |

Per service — pinned versions an advisory names, how many of those are malware,
how many have no fixed version at all, and how many distinct dependency chains
lead to them:

| service | hits | malicious | unfixable | chains | worst exposure (days) |
|---|---|---|---|---|---|
| `checkout-api` | 61 | 0 | 0 | 16 | 2,926.8 |
| `admin-dashboard` | 46 | 0 | 1 | 12 | 2,591.8 |
| `data-worker` | 36 | 0 | 0 | 3 | 2,344.8 |
| `typosquat-incident` | 20 | 5 | 7 | 8 | 2,170.8 |

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

Query latency on that graph, per service, worst case across the four: depth
profile 1,465 ms, choke points 536 ms, lookalikes 208 ms, blast-radius paths
46 ms, direct hits 90 ms, exposure windows 50 ms. Ingest wrote 22,174 rows in
1.94 s; the 226,817-advisory dump was parsed in 10.4 s; `selftest` put all
24 checks against a live node in 0.15 s, and `serve --selfcheck` drove all 14 API
checks over HTTP against the same graph.

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

CI runs the suite, then starts a real HydraDB node and runs `selftest`, the
ingest, the traversals and the API self-check against it, publishing
`artifacts/selftest.json`, `artifacts/ingest.json`, `artifacts/results.json`,
`artifacts/api.json` and the node's own logs.

`tests/unit/test_web.py` covers the API without a database, including a test that
the CI self-check *fails* on a graph with no hits — a check that cannot fail is
not a check.

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
