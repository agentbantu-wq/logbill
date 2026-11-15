# logbill

Find what's inflating your observability bill — before you pay for it.

`logbill` reads your logs (JSON-lines or plain text, from a file or stdin)
and/or Prometheus exposition metrics, and tells you which patterns are
eating the volume. It flags the waste Hacker News keeps paying for —
health-check / readiness-probe spam, Redis `PING` heartbeat traces, debug
logs in prod, exact duplicates, high-cardinality metric labels — prices
the volume at Datadog list prices and at a flat per-GB rate, and emits
ready-to-paste drop rules for Datadog, Vector, and the OpenTelemetry
Collector. Local-only by design: no telemetry leaves the machine.

## Why this exists

The demand is old and repeated. Still Unbuilt's "Logs and metrics on a
budget" (#99) collects 14 asks in 14 separate threads across 8 of 19
years, first asked in 2011 — half want open-source/self-hosted, 29% want
it local/private: "a cheap or free, easy-to-set-up alternative to
Datadog, Splunk or Sentry... self-hostable and pleasant to use at small
scale" (<https://stillunbuilt.shiptiffin.app/i/logs-and-metrics-on-a-budget/>).

The bills are real:

- "My log bill for Google cloud log would be like 30k. For splunk I
  like 80k. I self host for 1.5k per month." — HN, Feb 4 2026
  (<https://news.ycombinator.com/item?id=46893232>)
- "carefully price up buy vs build because buy gets extremely expensive.
  Last thing you want is a $500k bill for logging one day." — Ask HN,
  cloud deployments (<https://news.ycombinator.com/item?id=39836124>)
- Datadog logging "over $30k/mo" at ~24B messages/month — Ask HN, log
  management (<https://news.ycombinator.com/item?id=21949997>)
- In production environments analysed, 75% of logs were exact
  duplicates and 81% of trace data was Redis PING commands and
  health-check endpoints, with surprise bills of $130,000/month or more
  — Groundcover, Nov 2026
  (<https://www.groundcover.com/guides/datadog-alternatives-for-full-stack-observability-in-2026>)

A full Datadog/Splunk clone is *not* the missing piece — Still Unbuilt
itself notes 36 Show HN launches already do that job (SigNoz, HyperDX,
OpenObserve, ClickStack). The missing narrow slice is the audit:
which patterns, how much, what to drop. That's logbill.

## Quickstart

```bash
go build -o logbill .
./logbill --input examples/demo.log
cat app.log | ./logbill
./logbill --input app.log --md report.md --json report.json
```

Prometheus metrics:

```bash
curl -s localhost:9090/metrics | ./logbill --format prometheus
```

## What it does

- **Normalises** each log line into a template: timestamps, UUIDs, IPs,
  hex values, numbers and alphanumeric IDs (`abc123` → `<id>`) are
  stripped, so `GET /api/users/12345 … 42ms` and `GET /api/users/67890
  … 38ms` collapse into one pattern.
- **Ranks** patterns by count, bytes and share of volume.
- **Flags waste**: health-check / readiness-probe spam, heartbeat /
  PING traces, debug logs in prod, exact-duplicate lines, and any
  pattern with ≥10 occurrences and ≥5% of events.
- **Flags high-cardinality labels** in Prometheus metrics (≥100
  distinct values for a label).
- **Prices it**: Datadog list prices ($0.10/GB ingested +
  $1.70/million events indexed, 15-day retention) and a flat $0.50/GB.
- **Emits drop rules** for the wasteful patterns: a Datadog exclusion
  filter, a Vector remap snippet, and an OpenTelemetry Collector
  filter-processor YAML.

## Cost basis — read this

The monthly projection assumes the input is **one day of volume**.
If you know your real daily volume, pass it explicitly:

```bash
./logbill --input app.log --daily-gb 12 --daily-events 24000000
```

`--sample` truncates example lines to 120 characters, for sensitive logs.

## Example

```
$ ./logbill --input examples/demo.log --daily-gb 12 --daily-events 24000000
logbill — observability spend audit
events: 18   bytes: 1464 (0.00 MB)
wasteful: 14 events (77.8%), 1044 bytes
monthly cost if this is one day of volume: Datadog $1260.00  |  flat $0.50/GB $180.00

count  share    bytes      pattern
10     55.6   % 740        GET /healthz <n>  ← health-check / readiness-probe spam
2      11.1   % 204        GET /api/users/<n> from <ip> took <n>ms
2      11.1   % 168        cache miss for key <id>  ← debug logs in prod
2      11.1   % 136        Redis PING  ← heartbeat / PING trace
```

## Limitations

- The monthly cost is a projection from the volume you feed it, not a
  bill — use `--daily-gb` / `--daily-events` for your real volume.
- Prometheus cardinality is computed from the series in the input; a
  single scrape sees only the series that exist at that moment.
- Drop rules match on the most distinctive literal fragment of each
  wasteful template — review them before pasting into production.

## Tests

```bash
go test ./...
```

## License

MIT — see [LICENSE](LICENSE).
