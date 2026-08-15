# Evidence: how this project proves its own answers

Nothing in the README is hand-counted. Every number is read out of an artifact
written by a CI run against a live HydraDB node. This document holds the detail
behind that claim.

## Tests

```bash
pip install -e ".[dev]"
pytest tests/unit -q
```

The unit suite covers the parts where being quietly wrong would be invisible:
semver range matching (including prerelease rules), OSV timestamp parsing,
lockfile v1/v2/v3 shapes, id collision safety, advisory de-duplication, dependency
resolution against the recorded requirement, and row building.
`tests/unit/test_statements.py` additionally holds every statement to the rules
the database enforces — batch form, `MERGE` on `id` alone, no nulls, every field
present in every row, body-size-bounded chunks — so a violation fails in 0.2s
locally instead of minutes into a CI run.

Every command shown in the README is executed by CI, including the two that only
print for humans (`ask`, `stats`) — a documented command that nothing runs is a
documented command that quietly rots.

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

## What happens when a source is unreachable

The registry answers `429` when it is asked too much, and the fetcher retries
with a backoff — the server's own `Retry-After` when it sends one, capped so a
`Retry-After: 3600` cannot park an ingest for an hour. When the retries run out
the package is missing from the graph — and with it, its versions, its
dependencies and its maintainers, which makes every chain that would have crossed
it disappear. A blast radius that is too small reads as safety, so this is not a
warning:

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

## The failure paths, proved

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
"read-only" is enforced by the server rather than asserted in a README.

## Checked against a different source

Everything in the pipeline reads one OSV snapshot through one parser, so a
parsing mistake would be invisible: every test would agree with the code that
made it. `blastradius crosscheck` samples the hits this run produced and asks
`api.osv.dev` about each advisory directly, comparing five things — that OSV
agrees the exact version is affected, the disclosure date, the severity, whether
a fix exists, and malware vs vulnerability. The semver comparison it uses is
written from scratch in `crosscheck.py` and does not import the pipeline's
`versions` module, because two independent implementations agreeing is evidence
and one module agreeing with itself is not.

```
ok   minimist@1.2.0     GHSA-xvch-5gv4-984h   range [1.0.0, 1.2.6)
ok   ws@7.2.0           GHSA-6fc8-4gx4-v693   range [7.0.0, 7.4.6)
ok   axioss@1.6.2       MAL-2025-15242        range [0, open)
24/24 compared hits agree on affectedness, disclosure date, severity, fix availability and kind
```

The counts are reported separately on purpose: `checked` is how many hits were
sampled, `compared` is how many OSV could actually be reached about, and `agreed`
is how many of *those* matched. A hit OSV could not be reached about is counted
as `unreachable`, never folded into agreement — an outage at OSV is not evidence
that the graph is right.

`tests/unit/test_contract.py` then runs those checks against fake servers that
each break one clause on purpose — one that accepts any token, one that answers a
wrong graph with an empty result, one that accepts writes and stores nothing, one
that duplicates rows on rewrite — and requires the matching check to fail. A test
suite that only proves the good case proves nothing.

## Honest verdicts

Where the graph cannot support an answer, the answer says so rather than
defaulting to something reassuring:

* a pinned version whose fixed release is not in the graph reports
  `unknown: fixed version not in graph`, not "resolved";
* a lockfile v1 tree records whether a package was named in the manifest
  (`direct_source: manifest`) or only inferred from hoisting
  (`direct_source: inferred`), instead of calling every hoisted entry direct;
* a child edge is only drawn when the recorded requirement actually admits that
  version;
* every truncated list is reported as truncated, with the limits living in one
  place (`src/blastradius/limits.py`) so the UI and the CLI cannot drift apart.
* an exposure whose chain the graph cannot explain within the hop limit is
  reported as unexplained with no depth, never as "reached at up to 0 hops",
  which would read as a direct dependency.

## What review rounds changed

The suite carries one file per review round, each test named for the wrong
answer it prevents rather than for the function it calls:

* `tests/unit/test_review_regressions.py` — withdrawn advisories were not
  skipped, versions were sorted lexicographically (`1.10.0` below `1.9.0`), a
  missing disclosure date raised instead of reading as unknown, and an npm
  `Retry-After` could stall an ingest for minutes.
* `tests/unit/test_accuracy_regressions.py` — verdicts stated more confidently
  than the graph supported, requirement-blind child resolution in lockfile v1
  trees, crosscheck counters that mixed "unreachable" into "disagreed", and
  traversal limits scattered as magic numbers.
* `tests/unit/test_round3_regressions.py` — a stated non-UTC capture time was
  relabelled as UTC instead of converted (moving every "were you shipping it
  while it was live" answer by the offset), the exposure summary claimed
  "0 hop(s)" when no depth was known, the independent semver comparator ordered
  `1.0.0-9` above `1.0.0-10`, and the UI built click handlers by interpolating
  names into `onclick` attributes — HTML escaping applied to what the parser
  then hands to JavaScript, so values now travel in data attributes read back as
  text by one delegated listener.
* `tests/unit/test_selftest.py` — the module CI runs first had no offline
  coverage: a rejected statement is now proven to be recorded with the server's
  own code rather than raised, a read that answers nothing is proven to be a
  failure rather than a pass, and the fixture is proven to be deleted even after
  a failed check.

`ci/unit.sh` runs `ruff check` before the suite, so style and dead-import drift
fails the build instead of the reader's attention.
