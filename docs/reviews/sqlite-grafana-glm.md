# Independent review — PiHoleWatch f26d4eac vs baseline f62a517bf

**Reviewer seat:** static adversarial review of supplied bytes only. I did not execute tests, the experiment, the mutation check, or any runtime measurement, and I assert none. Where I rely on the author's recorded observations I say so; where I can cross-check recorded numbers against each other or against documented native semantics, I did.

## What the delta actually is (verified by diff-reading)

- `pihole_watch/findings.py`: `connect()` docstring, comment, and `PRAGMA journal_mode` value WAL→DELETE. **Every other byte of the file is identical to baseline** — schema, migrations, DAOs, `__all__`. Confirmed by line-by-line comparison against the supplied baseline owner.
- New: `tests/test_grafana_read_contract.py` (2 tests), `docs/sqlite-grafana-read-contract.md`, `compare.py`, two `results.json`.
- README: WAL guidance absent everywhere (I searched; no surface presents WAL as current — p satisfied at source level); rollback-journal rationale and conversion pointer added.
- Grafana configuration, `main.py`, `cli.py`, datasource YAML: unchanged. `main` still closes its connection in `finally` (the lifecycle fact the whole repair rests on — anchor `pihole_watch/main.py` finally block).

Cross-check of recorded evidence: every number quoted in the doc's two evidence sections matches the supplied `results.json` files exactly (WAL overlap 156.99/680.69, DELETE 77.28/390.79, commits 0.0256/6.086 and 0.0574/7.860; corrected run 62.42/405.85, cold max 640.43, restarted max 463.05, commit 0.068/1.477; 206,193→206,214 = exactly 21 new run_log rows). The `compare.py` supplied corresponds to the corrected DELETE-only run, and its code does what the doc claims: streaming pairwise all-table row equality (including `sqlite_sequence`) after conversion and before any fixture write, `queryText` from `rawQueryText`, disposable container `rm -f -v`, read-only source via `mode=ro` + supported `backup()`, no production writes. The WAL failure mechanism (21/21 errors cold, 0/21 once writes materialize sidecars) is consistent with sqlite.org/wal.html#readonly and with the observed production failure, not contradicted by anything supplied.

## Confirmed findings

**F1 (confirmed, low magnitude — code, conversion moment).** `pihole_watch/findings.py`, `connect()`:

```python
conn.execute("PRAGMA journal_mode=DELETE")
```

Mechanism: per sqlite.org/pragma.html#pragma_journal_mode, switching a database out of WAL requires exclusive access; if it cannot be obtained (any other connection open, even a transient Grafana per-query connection), **the pragma returns the old mode ("wal") and raises no error**. The code discards the returned row, so the selection silently no-ops. Post-conversion this cannot recur (DELETE→DELETE always returns "delete"; nothing in the tree sets WAL anymore), so the only live inputs that reach it are (a) the one-time live conversion and (b) a restore from a WAL-era backup, both while a reader connection happens to be in flight. The failure is not fully silent at the system boundary — Grafana errors return loudly — but the producer's run records success with no attribution, and the fix window is exactly the moment this change exists for.

Relevance/proportionality: the deployment plan already declares "verifies SQLite's returned mode" at conversion with connections quiesced, which covers case (a) at near-zero residual. The smallest correction is one line — compare `fetchone()[0]` to `"delete"` and raise on mismatch (fail-loud at the owner boundary, recorded by `main`'s existing error path). Whether that one line is worth admitting under the Preamble, or the declared deployment verification suffices and this is accepted as residual, is the operator's call; I state both costs honestly rather than pick.

**F2 (confirmed, trivial — stale counts in a changed surface).** `README.md`: badge "tests-94 passing", Quick start "Tests (93 passing)", Project structure "91 tests (pytest)" and "16-panel dashboard", while the dashboard's own `_meta` and the Grafana section say 21 panels/targets, and the artifact's evidence records 109 passing. Structure also omits `discovery.py`, which `main.py` imports. Pre-existing, not introduced by this change, but README was modified in this delta and these numbers mislead a later reader about the artifact's actual state. Smallest correction: correct or delete the counts (deletion avoids recurrence and is the better maintenance direction). Not a defect in the authorized outcome; report as real and unworthwhile-to-block.

**F3 (confirmed, low — provenance gap for paired evidence).** `results.json` (sha256:2fc1b17815d9f6c4, the paired WAL/DELETE run) is committed, but the script that generated it is not in the artifact; the supplied `compare.py` loops `for mode in ('DELETE',)` and corresponds to the corrected run (7f70904537f1bff4) only. The paired run's method is described in prose in the doc, and its numbers are internally consistent, but H commits method *and* results together. The WAL-side numbers underwrite the rejection of the WAL alternative, so their generator should be reproducible. Smallest correction: reference the paired-run script's revision (or commit it) in the evidence doc. Evidence power of the conclusion is not overturned — the production failure itself plus native docs independently support it — but the record is incomplete as it stands.

## Unconfirmed

- **All runtime results** (105/105 queries, latency figures, 109-pass suite, mutation failures, container behavior): author observations. I verified their internal consistency and their agreement with native documented semantics; per l I do not report my inability to reproduce as absence of effect, and per the dispatch I do not claim execution.
- **README's baseline WAL content**: the baseline README was not supplied (only baseline `findings.py`), so "removes obsolete WAL setup" is accepted on the artifact's own header; I did confirm the candidate README carries no WAL guidance anywhere.
- **Test 1's WAL-mutation failure mode** (read-only open of a cleanly-closed WAL database failing) is consistent with the native read-only WAL contract and with both recorded observations, but SQLite version nuances here are exactly the kind of thing only execution settles; I flag the mutation-evidence claim as resting on the author's corrected isolated invocation, which the doc itself properly separates from the invalid earlier invocation.

## Refuted / phantom-scope challenge

- **No phantom mechanisms found.** The runtime delta is one pragma value plus a comment; no retry, mode-switching, migration framework, sidecar, or new budget was smuggled in. The two tests each name an observed failure (the production read failure; the conversion's record retention) and use the real owner and native SQLite — proportionate, not defensive padding. The experiment artifacts are required by H, not scope growth. Any correction for F1 must remain a single check, not grow into a conversion framework.
- **Refuted: "DELETE degrades the writer."** Recorded commit medians (0.057/0.068 ms) and max (7.86/1.48 ms) under full concurrent reader bursts are within Python sqlite3's 5 s default busy timeout by two-plus orders of magnitude against the 5-minute cadence; a commit lock timeout would surface loudly as a failed run via `main`'s existing error path, not as apparent success.
- **Bounded residual, correctly declared, not a defect:** read-only consumer hits a hot journal only if the producer dies mid-commit; the error remains an error and the next producer run recovers it — this is the boundary contract the outcome explicitly chose, and the doc says so.

## Axiom check (reviewer mode, on received bytes)

| Axiom | Falsification question | Result |
|---|---|---|
| 1 Truth | Does any surface duplicate or reconstruct the authoritative store, or present WAL as current? | CONFORMS — `compare.py` uses `backup()` from `mode=ro` source; conversion asserted by full row equality; no WAL text survives in README/candidate owner |
| 2 Cognition | Any new hand-curated enumeration or routing in the delta? | NOT EXERCISED — delta adds no enumeration decisions |
| 3 Antifragility | Does journal selection ignore the actual connection lifecycle (producer closes; consumer read-only, per-query)? | CONFORMS — `findings.py` `connect()`; matches main.py close-in-finally and the plugin's per-query open |
| 4 KISS | Any mechanism beyond the one-line owner correction? | CONFORMS — see phantom-scope section; nothing speculative admitted |
| 5 Boundaries | Can a conversion or query failure read as success? | CONFORMS with F1 noted — consumer/native errors remain errors and are documented as such (`README.md` Grafana section); F1's silent no-op is the one seam, reported |
| 6 Maintenance | Is superseded guidance removed and the touched surface left coherent? | CONFORMS with F2 noted — WAL removal complete; stale counts are adjacent debt in the modified file |
| Preamble | Is any added mechanism's expected failure cost below its own cost? | CONFORMS for what was added; F1's proposed one-line check is the marginal case, presented for adjudication rather than presumed |

## Out-of-delta observation (D, for operator adjudication only, not a finding on this artifact)

The unchanged compose file mounts the whole pihole-watch repo read-only into Grafana (`/home/pistrommy/projects/pihole-watch:/data/pihole-watch:ro`), which includes uncommitted `.env` (secrets) and `dynamic_config.json`. Pre-existing, explicitly outside this change's boundary; raised because F makes it adjudication territory, and this delta did not need to touch it.

## Disposition input and verdict

- F1: fold the one-line mode check **or** accept as residual covered by the declared conversion-mode verification — either disposition is defensible; the check's entire protective value is the conversion/restore moment.
- F2: fold (trivial edit) or close without action as outside the authorized outcome.
- F3: fold (reference the paired script revision) — cheap, completes H's provenance requirement.

Remaining gates the artifact itself declares — live quiesced conversion, mode verification, distinct deployed-effect verification (d: this delta review does not satisfy it), operator verdict — are correctly outstanding and none of my findings blocks proceeding to them.

**I would not block.** The surviving defect classes I expect are exactly those named above (conversion-moment mode verification, stale README numerics, paired-evidence provenance); I name no further class, so from this seat review ends at their disposition.
