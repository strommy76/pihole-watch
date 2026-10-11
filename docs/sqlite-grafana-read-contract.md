# PiHoleWatch SQLite / Grafana read contract

## Authorized increment — 2026-10-11

Bryan approved the proposed bounded runtime comparison and owner-side repair at
12:25 EDT. Input: PiHoleWatch f62a517bf18b6728e345c58535412affa63d8683;
Grafana deployed configuration d7d1e80, now landed unchanged in main 29f30086.

Observed failure: the real Grafana SQLite datasource returns HTTP 400, unable to
open the database. The producer's `findings.connect` selects WAL; `main` closes
its connection after each run. The readable main database has WAL header bytes,
but no WAL/shared-memory sidecars, and the consumer's mount is read-only.
This is a lifecycle/access mismatch, not evidence of corruption or lost data.
SQLite's documented read-only WAL requirements explain the failure. The last
producer run observed at 12:06:20 EDT exited successfully.

Outcome: retain the same records, database owner and read-only Grafana boundary;
actual panel queries must return committed data across producer writes/closes and
reader restart, and native errors must remain errors. Producer owns recovery.

Execution: first compare the current WAL baseline and rollback DELETE candidate
on a consistent local SQLite backup with the real pinned Grafana image/plugin,
actual owner panel SQL and existing producer DAO writes. Use an isolated,
loopback-only disposable Grafana, never reset or probe-write production. Cover
normal overlapping queries/commits, last-writer close and reader restart. Record
query/write latency and errors; do not introduce a performance framework or
arbitrary new runtime budgets. Evaluate the candidate against the existing
five-minute producer and dashboard cadence. If meaningful contention rules it
out, investigate a supported WAL lifecycle correction within this boundary,
raising any required additional mechanism or access expansion before acting.

Implement only the selected existing owner connection correction, corresponding
tests and removal of superseded WAL setup guidance. No new service, polling loop,
snapshot publisher, broad database migration, automatic mode switching, invented
sidecars, immutable flag on live data, or writable Grafana project mount.

### C/H, review and deployment

The owner correction and regression tests are permanent runtime work. The
comparison is short-lived experiment work; its method, inputs and results are
recorded here, not made a maintained runtime mechanism. The disposable database
is a derived experiment input, not authoritative state; the production database
and its records remain authoritative and are neither rebuilt nor replaced.

Failure could be silent (wrong/stale reads) or irreversible (unsafe journal/data
handling), so k fires. One branch and PR in PiHoleWatch. Whole named artifact and
its actual owner/consumer seams receive Astra/OpenAI and GLM-5.3/Ollama review,
individually adjudicated under axiom-check, then pi-Claude review. Distinct live
effect verification follows reviewed publication. Operator verdict lands the PR.

Live deployment, after source review, quiesces the existing writer and consumer
connections for native journal conversion if required; verifies SQLite's returned
mode and records preserved; restores the existing schedules and validates actual
producer writes and Grafana SQL. Do not delete sidecars or recreate the store.
Revert the connection correction and native journal selection with connections
quiesced, retaining the same data and existing read-only mount. Conversion or
query failure surfaces at its native boundary; no fallback reads as success.

### Construction axiom-check

| Axiom | Falsification question | Result |
|---|---|---|
| 1 Truth | Rebuild records or duplicate owner? | CONFORMS |
| 2 Cognition | Add curated routing or switching? | CONFORMS |
| 3 Antifragility | Ignore actual connection lifecycle changes? | CONFORMS |
| 4 KISS | Add mechanisms without observed need? | CONFORMS |
| 5 Boundaries | Hide failed conversion or query? | CONFORMS |
| 6 Maintenance | Change unrelated services or owners? | CONFORMS |
| Preamble | Protect an unobserved hypothetical input? | CONFORMS |

Locations: the execution/outcome paragraphs retain the existing owner and actual
queries, specify lifecycle measurement and admit only a measured correction.
C/H preserves the authoritative store, declares errors and native revert, bounds
review and publication; scope exclusions forbid unrelated mechanisms. These
prospective checks admit the execution shape, not unperformed runtime results.

Primary sources:
[SQLite WAL/read-only contract](https://sqlite.org/wal.html#readonly),
[journal-mode selection](https://sqlite.org/pragma.html#pragma_journal_mode),
[rollback locking/recovery](https://sqlite.org/lockingv3.html).

## Experiment and implementation evidence

Pending. No live journal conversion or corrective deployment performed.
