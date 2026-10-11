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

### Native runtime comparison — 12:28–12:35 EDT

Production source f62a517. Obtain a consistent local input with Python SQLite's
supported `source.backup(destination)` from `file:.../findings.db?mode=ro`.
The source connection creates/cleans SQLite's own transient coordination files
as necessary but never writes observation records. No backup replaces live data.
Copies, provisioning and disposable data stayed in a private task directory.

Run an isolated Grafana with the actual pinned image
`grafana/grafana@sha256:1c1bd67c54c5fcf6e759897852b5a584191bd6796e8d328a5ace457799801261`,
UID/GID 1000, the installed signed frser-sqlite-datasource 4.0.6 mounted read-only,
and each copy's database directory mounted read-only. Expose only an OS-assigned
loopback port, with an experiment-only credential and no production accounts or
state. Disable native analytics/update checks; never install another plugin.

Method: generate targets from every actual owner dashboard panel. The plugin's
installed frontend `applyTemplateVariables` assigns native backend `queryText`
from `rawQueryText`; no owner SQL contains template variables, so use the exact
SQL unchanged in that required API field. Send each target to `/api/ds/query`
with the owner's six-hour range, one concurrent reader per actual target (21):

1. Apply owner schema to an isolated copy; select candidate mode through native
   SQLite and close the writer before starting the reader.
2. Query all targets cold, then reopen the writer and repeat all targets.
3. Concurrently query all targets and commit 21 real `findings.record_run` calls,
   representing a write burst alongside a complete dashboard refresh. Each call
   uses the existing DAO, supplied query count 1 and zero findings. This is not
   a replay of every detector or triage operation.
4. Close the writer and query all targets again; restart only the isolated
   Grafana, read back its newly assigned loopback port, and repeat all targets.
5. Count actual response errors and returned rows, timing individual requests
   and DAO calls with `time.monotonic`. Never print returned private values.
   Remove the exact disposable container including its disposable anonymous
   state volume after each mode; do not touch the production container/volume.

The first attempt stopped on stale ephemeral port after reader restart; corrected
the method to read native port assignment again. A second attempt omitted the
frontend's required backend field and therefore did not execute panel SQL; its
empty frames/error counts are invalid evidence and were discarded, not reported
as successful queries. Those method errors do not justify production code.

Valid paired fixture comparison (12:32 EDT, current-sized consistent input):

| Stage | WAL errors/queries | DELETE errors/queries |
|---|---|---|
| Cold reader | 21/21 | 0/21 |
| Writer open, no writes | 21/21 | 0/21 |
| Concurrent writes/reads | 0/21 | 0/21 |
| Writer closed | 21/21 | 0/21 |
| Reader restarted | 21/21 | 0/21 |

WAL succeeds only after actual writes create coordination files in this
observation; reopening a connection alone is insufficient. DELETE overlap query
median/max: 77.3/390.8 ms; DAO commit median/max: 0.057/7.860 ms. WAL overlap
query median/max: 157.0/680.7 ms, commit median/max: 0.026/6.086 ms. One paired
observation is not statistical evidence of general throughput superiority, nor
does a failed query's quick return measure useful performance. The fixture-only
paired comparison used distinguishable future run timestamps; those artificial
freshness values are not evidence of production freshness.

### Actual corrected owner verification — 12:34–12:35 EDT

Changed the existing `findings.connect` journal selection to DELETE; no new
dependency, service, permission, retry, tuning value or store. Reran the isolated
procedure importing the actual corrected owner from this branch, including the
writer's reopen through `findings.connect`, and using current UTC timestamps for
the fixture writes. Before any new fixture writes, compare every existing row
in every native-discovered SQLite table, including sqlite_sequence, between
input and converted copy: pairwise `SELECT * ORDER BY rowid`, streaming rows,
all equal. This is a content comparison, not a digest or count-only proxy.

All 105 actual panel queries succeeded: 21 each cold/open/overlap/closed/restarted.
Cold/open bursts returned 206,193 total frame rows; each later burst 206,214,
including the 21 newly committed fixture run records. Some time-series frames
repeat their time values across series; these totals are response rows, not
unique database records. Actual corrected overlap query median/max:
62.4/405.9 ms; cold maximum 640.4 ms; restarted maximum 463.0 ms.
Actual DAO commit median/max: 0.068/1.477 ms. These measured nominal operations
fit the existing five-minute collection/refresh cadence with no added budget.
No evidence from this current workload justifies a larger WAL mechanism.

Runtime concurrency measurement is bounded to actual panel SQL and run-record
DAO commits; it does not establish every future load, database growth, arbitrary
long-held reader transaction, detector mix or power-loss outcome. SQLite retains
transaction/recovery ownership; a read-only reader encountering unrecovered
journal state fails until the existing writer recovers it. No synthetic success.

The repository-local interpreter ran the full suite: 109 passed in 0.68 s.
New tests directly use native SQLite and the real owner: initial and subsequent
closed-store reads with a filesystem-read-only directory, and existing WAL
records preserved through owner-selected mode conversion. Their expectations
come from supplied records and the declared journal contract, not execution
snapshots. For r, copy actual owner bytes and replace only DELETE with WAL:
both new tests fail (read-only open and wrong retained mode). An initial mutation
invocation imported the unmutated test project's owner through pytest's path
precedence; that invocation is invalid evidence. The corrected isolated copied
test invocation imports the mutated owner and gives 2 failures in 0.04 s.

The actual prototype/container behavior, source correction and targeted mutation
support this selected repair; the unmutated full-suite pass alone does not prove
native Grafana behavior or production data preservation.

## Remaining gates

No live conversion or corrective deployment performed. Whole-artifact independent
reviews, disposition, pi-Claude review and distinct live effect checks remain.
