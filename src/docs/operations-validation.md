# Operations and release validation

Use the locked environment from `src/`:

```sh
uv sync --dev --locked
uv run python -m pytest
uv run python -m ruff check .
uv run python -m ruff format --check .
uv run python -m pyright
uv build
uv run python scripts/pty_smoke.py
```

After moving a checkout, create a fresh virtual environment instead of copying its
scripts. Use `UV_PROJECT_ENVIRONMENT=/tmp/socketclaw-check-venv` with `uv sync`
and `uv run`. Use `python -X pycache_prefix=/tmp/socketclaw-check-cache -m pytest`
if an old Python cache refers to the previous checkout path. Never accept a new
snapshot baseline solely to hide a stale cache error.

The `Quality gate` workflow runs on Linux and macOS with Python 3.11 and 3.14.
It runs static checks, all tests, a dependency audit and package builds. The built
wheel is installed in a separate environment and exercised through migration,
doctor and actual terminal input. The macOS standalone release workflow requires
this workflow to succeed before either architecture builds. Both executables must
pass the PTY smoke before artifacts can be published. Network failure during the
audit fails the gate; vulnerabilities have no implicit allowlist.

`pty_smoke.py` creates an isolated home and only monitors localhost. At both 80x24
and 120x36 it completes the real first-run flow, skips the optional API key,
replaces the initial target with 127.0.0.1 and starts monitoring. It verifies the
saved configuration and a successful real loopback observation in SQLite before
navigating and resizing through 60x18, 120x36 and 80x24. It also checks cancellation
at Welcome and startup with an existing configuration, for six PTY processes in
total. Every process must exit cleanly with Ctrl+C without worker errors or
scrollback erasure. Completed setup must leave no credentials or investigations,
and cancellation must not save configuration. This is a terminal lifecycle smoke,
not a claim that every control has been visually inspected. Pass
`--executable /path/to/socketclaw` to check a frozen executable.
Windows requires separate terminal validation; the PTY harness is POSIX only.

## Dependency assessment

On 2026-09-26 the old AnyIO 4.13.0 lock was affected by
[GHSA-82r6-8w77-94w6](https://github.com/agronholm/anyio/security/advisories/GHSA-82r6-8w77-94w6)
and
[GHSA-5p39-cfhj-2xmp](https://github.com/agronholm/anyio/security/advisories/GHSA-5p39-cfhj-2xmp).
Both advisories identify 4.14.2 as patched. The minimum is now 4.14.2 and the lock
selects 4.15.1. The fixed ASCII OpenAI endpoint does not present the international
domain TLS trigger. The application uses asyncio subprocess calls, not AnyIO's
process-pool worker interface. These observations limit known reachability and
do not replace the update or constitute a claim about all future integrations.
The development pytest lock was also updated after the audit reported
PYSEC-2026-1845 for 9.0.2. The complete exported production and development lock
passed pip-audit after these updates.

To reproduce the audit without resolving different versions:

```sh
uv export --locked --no-emit-project --format requirements-txt --output-file /tmp/socketclaw-requirements.txt
uv run python -m pip_audit --disable-pip --require-hashes -r /tmp/socketclaw-requirements.txt
```

CI coverage is configured by these changes. Local execution on one macOS host
does not establish that hosted Linux or both macOS release architectures have
already passed. Paid model tests remain explicitly opt-in.

## Capacity measurements

```sh
uv run python scripts/benchmark_operations.py --batches 5
uv run python scripts/benchmark_operations.py --batches 1 --history-days 30 90
```

The harness prints JSON Lines with hardware, Python version and individual burst
samples for 100, 500 and 1000 observations. Consecutive batches share one database
so growth in correlation history remains visible. Five samples provide only a
coarse p95 estimate. Run on an otherwise quiet host and record concurrent work.
A result above the proposed two-second target is a missed target, not a passing
performance test. Timing measurements are deliberately not flaky CI assertions.

The history option seeds 18,720 synthetic normal observations per day by default,
matching the documented five-second ping and one-minute scan schedule. Its 30-day
and 90-day databases contain 561,601 and 1,684,801 rows including one provenance
seed. This is a row-count capacity model. It does not reproduce real log sizes,
90 days of WAL churn or the cost of a full production collector. Each run measures
recent queries, full domain validation, a 100-observation JSON export, retention
preview, one bounded cleanup and restart validation. The harness uses a private
temporary directory and deletes it after the run. Reserve several gigabytes for
the database and mandatory backup. `--daily-events 100` is a fast harness check,
not evidence for production capacity.

For a sustained input model, add `--sustained-seconds 30 --input-rate 100`.
The source produces synthetic authentication failures independently of the
collector. A second job checks a real local TCP listener every second. The result
includes backlog maxima for both halves, remaining backlog, pending commits,
service check count and maximum check interval. Source queue drainage has a
30-second deadline. Evaluate those numbers together; a drained queue after the
input stops alone does not prove stable live throughput.

### Local measurement, 2026-09-26

On an Apple M5 with 16 GiB RAM, macOS 27 arm64 and Python 3.11.15, five
consecutive batches after the correlation index change gave a 1,000-observation
median of 1.484 seconds and a coarse p95 of 1.564 seconds. The 500-observation p95
was 0.812 seconds. These are local observations, not minimum hardware guarantees.
Other implementation work was occurring on the same workstation.

| Normal history | Rows | Database size reported | Query 100 | Full diagnostic | Backup and bounded cleanup |
| --- | ---: | ---: | ---: | ---: | ---: |
| 30-day model | 561,601 | 546 MB | 0.0024 s | 12.27 s | 4.86 s |
| 90-day model | 1,684,801 | 1.58 GB | 0.0025 s | 40.73 s | 10.50 s |

Both models exported 100 observations in about 0.03 seconds and passed validation
after restart. Each cleanup deleted 10,000 eligible records and created a backup.
The 90-day preview found 1,160,640 eligible records, so repeated bounded cleanup
is required to finish that backlog. Full diagnostic cost remains substantial at
this scale and should be scheduled accordingly. SQLite can reuse freed pages;
deleting rows does not promise immediate reduction of the database file.

The 30-second sustained run at 100 input events per second generated and committed
2,994 observations. Peak backlog was 57 and final backlog and pending batches
were zero. Backlog maxima were 53 and 57 in the two halves. The local TCP service
was checked 31 times with a maximum interval of 1.003 seconds, with no collector
error. The harness pauses new scheduling and waits for active collectors before
its final count, so shutdown cancellation is not mistaken for dropped input.
Longer deployment soak tests and operator usability measurements remain separate
validation work.
