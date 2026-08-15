# Demo video — script and storyboard (target 2:50, hard cap 3:00)

Narration is written to ~150 words per minute. Total ≈ 420 words. Record screen
at 1920×1080, terminal at 16–18pt, browser at 100% zoom, no notifications.

---

## Scene 1 — The hook (0:00 – 0:18)

**On screen:** black title card, one line of text, then cut to a terminal that
already has `blastradius incident axioss` typed but not run.

> **Narration:** "A package you depend on was just flagged as malicious. You have
> minutes to answer three questions: which of my services are exposed, through
> which dependency chain, and were they exposed at the moment it mattered. Every
> scanner I know answers the first one badly and the other two not at all."

**Title card text:** `blastradius — supply-chain blast radius on HydraDB`

---

## Scene 2 — Why upgrading is not an answer (0:18 – 0:38)

**On screen:** run `blastradius stats`, let the counts land, then hold on the
`MAL-*` line. Overlay the README table (four rows only).

> "This is the whole OSV npm corpus, counted by this project on every CI run:
> 226,000 advisories, 96.8 percent of them malicious packages — and 26 of those
> offer a fixed version. Twenty-six. When the package is malware there is nothing
> to upgrade to, so 'reachability' is the only useful question left, and
> reachability is a graph question."

---

## Scene 3 — The six answers, from the command line (0:38 – 1:12)

**On screen:** press enter on `blastradius incident axioss`. Speed the output up
2× if needed, then stop-scroll on: exposed services, first affected version,
`resolved while live` verdicts, sibling packages by maintainer, typosquat pair,
full chains. Highlight each block with a soft box as it is named.

> "One command, six answers, one graph. Two services exposed. The exact version
> that introduced it, with its publish date. Which lockfiles resolved it while it
> was live and nobody knew — that one needs time in the graph, not just
> dependencies. The other packages the same npm account can publish, which is how
> takeovers spread. The package it impersonates, with both download counts. And
> every dependency chain, hop by hop — because the chain is the answer, not a
> yes-or-no."

---

## Scene 4 — The same graph, as a UI (1:12 – 1:52)

**On screen:** `blastradius serve`, browser to the service view for
`typosquat-incident`. Click a hit → package view for `axioss` → click a hop in a
chain → maintainer view → lookalikes view. Slow, deliberate clicks; one hover per
view.

> "The UI is the same queries, nothing precomputed. Here is a service: its hits,
> how deep they sit, its choke points, its exposure windows. Click a hit and you
> get the incident view for that package — every service it reaches and the chain
> to each one. Every hop is clickable, so you can walk the graph the way you
> would reason about it. Maintainer view answers 'if this account were taken
> over, what does it touch'. Search is a prefix query inside the database, not a
> filter in Python."

---

## Scene 5 — Why HydraDB (1:52 – 2:22)

**On screen:** split view — `src/blastradius/queries.py` with the `algo.MSpaths`
call on the left, the rendered chain on the right. Then flash the failing
upward-traversal error message from `docs/DESIGN.md`.

> "The reverse question — who depends on this — is one `algo.MSpaths` call with
> incoming direction, and it returns the intermediate hops, so the path comes out
> of the database already ranked. Writing it the obvious way, as a
> variable-length match against the arrow, the server refuses: it needs a fixed
> source id. That is the kind of thing you only find by reading the server's
> source, and it is why this is built on the path procedures rather than around
> them. Ingest is batched `UNWIND` upserts with stable ids, so a re-run is
> idempotent."

---

## Scene 6 — Why you can believe the numbers (2:22 – 2:45)

**On screen:** GitHub Actions run, green, expanding to show the HydraDB container
job; then `artifacts/osv-crosscheck.json` and `artifacts/contract.json`.

> "Every number in the README is read from a CI artifact, not typed in. CI starts
> a real HydraDB node in Docker, runs the ingest and all the traversals, then
> checks its own answers against the live OSV API with a second, independent
> semver implementation. It also asserts the failure paths: a wrong token, a
> wrong graph, a write that returned 200 and stored nothing. And where the graph
> can't support an answer, it says unknown instead of guessing."

---

## Scene 7 — Close (2:45 – 2:55)

**On screen:** return to the service view, then the repo URL and licence.

> "blastradius. Open source, Apache-2.0, everything you just saw reproducible
> with one docker run and one command."

---

## Recording checklist

- [ ] Clean terminal, no prompt clutter, `PS1='$ '`
- [ ] Graph pre-ingested before recording (ingest itself is not on camera)
- [ ] 1920×1080, 30fps, screen recording only — no webcam
- [ ] Narration recorded separately, then laid under the screen capture
- [ ] Captions burned in (judges may watch muted)
- [ ] Final length under 3:00 — check before upload
- [ ] Upload unlisted to YouTube; put the link at the top of the README
