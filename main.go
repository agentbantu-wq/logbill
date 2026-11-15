// Package main implements logbill: a local-only CLI that audits
// observability spend by finding the log patterns and metric series
// that inflate the bill, and emitting ready-to-paste drop rules.
//
// It reads JSON-lines logs (from a file or stdin) and/or Prometheus
// exposition-format metrics, normalises each log line into a template
// (timestamps, UUIDs, IPs and numbers stripped), ranks patterns by
// count and bytes, flags the classic waste — exact duplicates,
// health-check / readiness-probe spam, heartbeat traces and debug
// logs in prod — and prices the volume at Datadog list prices and at
// a flat per-GB rate. Nothing leaves the machine.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Cost model defaults (Datadog list prices, 15-day retention).
const (
	datadogPricePerGB        = 0.10 // $ per GB ingested
	datadogPricePerMEvents   = 1.70 // $ per million events indexed
	flatPricePerGB           = 0.50 // $ per GB, flat-rate alternative
	highCardinalityThreshold = 100  // distinct label values that count as high cardinality
	wasteShareThreshold      = 0.05 // a pattern is "noisy" at >= 5% of volume
)

var (
	uuidRe      = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	ipv4Re      = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	hexRe       = regexp.MustCompile(`\b0x[0-9a-fA-F]+\b`)
	numberRe    = regexp.MustCompile(`\d[\d,]*(?:\.\d+)?`)                     // digit runs anywhere: 42ms -> <n>ms
	idTokenRe   = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9]*\d[a-zA-Z0-9]*\b`) // abc123, def456 -> <id>
	tsRe        = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b`)
	quotedRe    = regexp.MustCompile(`"[^"]{24,}"`)
	spaceRe     = regexp.MustCompile(`\s+`)
	healthRe    = regexp.MustCompile(`(?i)(/healthz?|/ready|/readiness|/live|/liveness|health[-_ ]?check)`)
	heartbeatRe = regexp.MustCompile(`(?i)\b(PING|PONG|heartbeat|keep[-_ ]?alive)\b`)
)

// Pattern is one normalised log template and its aggregates.
type Pattern struct {
	Template string         `json:"template"`
	Count    int            `json:"count"`
	Bytes    int64          `json:"bytes"`
	Share    float64        `json:"share_of_events"`
	Example  string         `json:"example"`
	Levels   map[string]int `json:"levels"`
	Reasons  []string       `json:"waste_reasons,omitempty"`
	Waste    bool           `json:"wasteful"`
}

// MetricSeries summarises one Prometheus metric family.
type MetricSeries struct {
	Name          string                     `json:"name"`
	Series        int                        `json:"series"`
	LabelCardinal map[string]int             `json:"label_cardinality"`
	HighCard      []string                   `json:"high_cardinality_labels,omitempty"`
	Example       string                     `json:"example"`
	labelValues   map[string]map[string]bool `json:"-"`
}

// Report is the full audit result.
type Report struct {
	Events         int             `json:"events"`
	Bytes          int64           `json:"bytes"`
	Patterns       []*Pattern      `json:"patterns"`
	Metrics        []*MetricSeries `json:"metrics,omitempty"`
	WasteEvents    int             `json:"waste_events"`
	WasteBytes     int64           `json:"waste_bytes"`
	WasteShare     float64         `json:"waste_share_of_events"`
	MonthlyDatadog float64         `json:"monthly_cost_datadog_usd"`
	MonthlyFlat    float64         `json:"monthly_cost_flat_usd"`
	CostBasis      string          `json:"cost_basis"`
	Rules          Rules           `json:"drop_rules"`
}

// Rules are ready-to-paste drop/sample rules for the wasteful patterns.
type Rules struct {
	Datadog string `json:"datadog_exclusion_filter"`
	Vector  string `json:"vector_remap"`
	OTel    string `json:"otel_collector_filter"`
}

func main() {
	var (
		input   = flag.String("input", "", "log file to read (default: stdin)")
		format  = flag.String("format", "auto", "input format: auto, jsonl, text, prometheus")
		mdOut   = flag.String("md", "", "write Markdown report to this file")
		jsonOut = flag.String("json", "", "write JSON report to this file")
		topN    = flag.Int("top", 10, "number of top patterns to show")
		dailyGB = flag.Float64("daily-gb", 0, "daily ingested volume in GB (overrides the 1-day assumption for cost projection)")
		dailyEv = flag.Float64("daily-events", 0, "daily event count (overrides the 1-day assumption for cost projection)")
		sample  = flag.Bool("sample", false, "sample mode: truncate each example line to 120 chars (for sensitive logs)")
	)
	flag.Parse()

	var in io.Reader = os.Stdin
	if *input != "" {
		f, err := os.Open(*input)
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		in = f
	}

	rep, err := Analyze(in, *format, *topN, *dailyGB, *dailyEv, *sample)
	if err != nil {
		fatal(err)
	}
	printHuman(rep, *topN)
	if *mdOut != "" {
		if err := os.WriteFile(*mdOut, []byte(renderMarkdown(rep)), 0o644); err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *mdOut)
	}
	if *jsonOut != "" {
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fatal(err)
		}
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *jsonOut)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "logbill:", err)
	os.Exit(1)
}

// Analyze reads the whole input and builds the report.
func Analyze(r io.Reader, format string, topN int, dailyGB, dailyEvents float64, sample bool) (*Report, error) {
	rep := &Report{CostBasis: "input treated as one day of volume (override with --daily-gb / --daily-events)"}
	patterns := map[string]*Pattern{}
	var totalBytes int64
	var totalEvents int

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if format == "prometheus" || (format == "auto" && isPrometheusLine(line)) {
			rep.Metrics = append(rep.Metrics, parsePrometheusLine(line)...)
			continue
		}
		totalEvents++
		totalBytes += int64(len(line)) + 1
		msg, level := extractMessage(line, format)
		tmpl := normalise(msg)
		p, ok := patterns[tmpl]
		if !ok {
			p = &Pattern{Template: tmpl, Levels: map[string]int{}, Example: msg}
			if sample && len(p.Example) > 120 {
				p.Example = p.Example[:120] + "…"
			}
			patterns[tmpl] = p
		}
		p.Count++
		p.Bytes += int64(len(line)) + 1
		if level != "" {
			p.Levels[strings.ToLower(level)]++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	rep.Events = totalEvents
	rep.Bytes = totalBytes
	for _, p := range patterns {
		if totalEvents > 0 {
			p.Share = float64(p.Count) / float64(totalEvents)
		}
		p.Reasons, p.Waste = wasteReasons(p)
		if p.Waste {
			rep.WasteEvents += p.Count
			rep.WasteBytes += p.Bytes
		}
		rep.Patterns = append(rep.Patterns, p)
	}
	sort.Slice(rep.Patterns, func(i, j int) bool {
		if rep.Patterns[i].Bytes != rep.Patterns[j].Bytes {
			return rep.Patterns[i].Bytes > rep.Patterns[j].Bytes
		}
		return rep.Patterns[i].Count > rep.Patterns[j].Count
	})
	if len(rep.Patterns) > topN {
		// Keep the full list in JSON, but the human view is capped by the caller.
		_ = topN
	}
	if totalEvents > 0 {
		rep.WasteShare = float64(rep.WasteEvents) / float64(totalEvents)
	}
	rep.Metrics = summariseMetrics(rep.Metrics)

	// Cost projection: monthly = daily volume x 30.
	gbPerDay := float64(totalBytes) / 1e9
	evPerDay := float64(totalEvents)
	if dailyGB > 0 {
		gbPerDay = dailyGB
		rep.CostBasis = fmt.Sprintf("user-supplied --daily-gb=%.2f", dailyGB)
	}
	if dailyEvents > 0 {
		evPerDay = dailyEvents
		rep.CostBasis += " + --daily-events"
	}
	rep.MonthlyDatadog = round2(30 * (gbPerDay*datadogPricePerGB + evPerDay/1e6*datadogPricePerMEvents))
	rep.MonthlyFlat = round2(30 * gbPerDay * flatPricePerGB)
	rep.Rules = buildRules(rep.Patterns)
	return rep, nil
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

// extractMessage pulls the human message and level out of a log line.
// JSON lines use msg/message/log + level/severity; plain text is used as-is,
// with a leading level token (INFO, DEBUG, WARN, ERROR) recognised.
func extractMessage(line, format string) (string, string) {
	if format != "text" && strings.HasPrefix(strings.TrimSpace(line), "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err == nil {
			msg := ""
			for _, k := range []string{"message", "msg", "log", "text"} {
				if v, ok := obj[k].(string); ok && v != "" {
					msg = v
					break
				}
			}
			level := ""
			for _, k := range []string{"level", "severity", "lvl"} {
				if v, ok := obj[k].(string); ok {
					level = v
					break
				}
			}
			if msg != "" {
				return msg, level
			}
		}
	}
	// Plain text: strip a leading ISO timestamp and level token.
	s := tsRe.ReplaceAllString(line, "")
	parts := strings.Fields(s)
	level := ""
	if len(parts) > 0 {
		switch strings.ToUpper(parts[0]) {
		case "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL":
			level = parts[0]
			s = strings.Join(parts[1:], " ")
		}
	}
	return strings.TrimSpace(s), level
}

// normalise collapses a log message into its template.
func normalise(msg string) string {
	s := tsRe.ReplaceAllString(msg, "<ts>")
	s = uuidRe.ReplaceAllString(s, "<uuid>")
	s = ipv4Re.ReplaceAllString(s, "<ip>")
	s = hexRe.ReplaceAllString(s, "<hex>")
	s = quotedRe.ReplaceAllString(s, `"<str>"`)
	s = idTokenRe.ReplaceAllString(s, "<id>")
	s = numberRe.ReplaceAllString(s, "<n>")
	return spaceRe.ReplaceAllString(strings.TrimSpace(s), " ")
}

// wasteReasons classifies a pattern as wasteful and explains why.
func wasteReasons(p *Pattern) ([]string, bool) {
	var reasons []string
	lower := strings.ToLower(p.Template)
	if healthRe.MatchString(lower) {
		reasons = append(reasons, "health-check / readiness-probe spam")
	}
	if heartbeatRe.MatchString(lower) {
		reasons = append(reasons, "heartbeat / PING trace")
	}
	if p.Levels["debug"] > 0 && p.Levels["debug"] == p.Count {
		reasons = append(reasons, "debug logs in prod")
	}
	// "Noisy" needs both share and a minimum count, so a small sample
	// does not flag every singleton pattern as waste.
	if p.Count >= 10 && p.Share >= wasteShareThreshold && len(reasons) == 0 {
		reasons = append(reasons, fmt.Sprintf("noisy pattern (%.0f%% of events)", p.Share*100))
	}
	// Exact duplicates: the same literal message repeated, with no
	// variables to normalise away.
	if p.Count >= 3 && !strings.Contains(p.Template, "<") {
		reasons = append(reasons, "exact-duplicate lines")
	}
	return reasons, len(reasons) > 0
}

// --- Prometheus exposition format ---

func isPrometheusLine(line string) bool {
	if strings.HasPrefix(line, "#") {
		return true
	}
	// metric_name{labels} value  or  metric_name value
	i := strings.IndexAny(line, "{ ")
	if i <= 0 {
		return false
	}
	name := line[:i]
	if !regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`).MatchString(name) {
		return false
	}
	rest := strings.TrimSpace(line[i:])
	return strings.HasPrefix(rest, "{") || isFloat(strings.Fields(rest)[0])
}

func isFloat(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// parsePrometheusLine returns one MetricSeries per data line (HELP/TYPE
// lines return nil); callers aggregate with summariseMetrics.
func parsePrometheusLine(line string) []*MetricSeries {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	name := line
	labels := map[string]int{}
	values := map[string]map[string]bool{}
	if i := strings.Index(line, "{"); i >= 0 {
		name = line[:i]
		j := strings.Index(line, "}")
		if j < 0 {
			return nil
		}
		for _, kv := range strings.Split(line[i+1:j], ",") {
			parts := strings.SplitN(strings.TrimSpace(kv), "=", 2)
			if len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				v := strings.Trim(parts[1], `"`)
				labels[k]++
				if values[k] == nil {
					values[k] = map[string]bool{}
				}
				values[k][v] = true
			}
		}
	} else if i := strings.Index(line, " "); i >= 0 {
		name = line[:i]
	}
	return []*MetricSeries{{Name: name, Series: 1, LabelCardinal: labels, Example: line, labelValues: values}}
}

// summariseMetrics aggregates per-line series into per-metric families
// and flags labels with >= highCardinalityThreshold distinct values.
func summariseMetrics(in []*MetricSeries) []*MetricSeries {
	byName := map[string]*MetricSeries{}
	order := []string{}
	for _, m := range in {
		agg, ok := byName[m.Name]
		if !ok {
			agg = &MetricSeries{Name: m.Name, LabelCardinal: map[string]int{}, Example: m.Example, labelValues: map[string]map[string]bool{}}
			byName[m.Name] = agg
			order = append(order, m.Name)
		}
		agg.Series++
		for k, v := range m.LabelCardinal {
			agg.LabelCardinal[k] += v
		}
		for k, vs := range m.labelValues {
			if agg.labelValues[k] == nil {
				agg.labelValues[k] = map[string]bool{}
			}
			for v := range vs {
				agg.labelValues[k][v] = true
			}
		}
	}
	out := make([]*MetricSeries, 0, len(order))
	for _, name := range order {
		m := byName[name]
		for label, vs := range m.labelValues {
			m.LabelCardinal[label] = len(vs)
			if len(vs) >= highCardinalityThreshold {
				m.HighCard = append(m.HighCard, label+" ("+strconv.Itoa(len(vs))+" distinct values)")
			}
		}
		sort.Strings(m.HighCard)
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Series > out[j].Series })
	return out
}

// --- Drop rules ---

func buildRules(patterns []*Pattern) Rules {
	var waste []*Pattern
	for _, p := range patterns {
		if p.Waste {
			waste = append(waste, p)
		}
	}
	if len(waste) > 5 {
		waste = waste[:5]
	}
	if len(waste) == 0 {
		return Rules{
			Datadog: "{\n  \"note\": \"no wasteful patterns found — nothing to drop\"\n}",
			Vector:  "# no wasteful patterns found — nothing to drop",
			OTel:    "# no wasteful patterns found — nothing to drop",
		}
	}
	var needles []string
	for _, p := range waste {
		// Use the most distinctive literal fragment of the template.
		needles = append(needles, distinctiveFragment(p.Template))
	}

	var dd strings.Builder
	dd.WriteString("{\n  \"exclusion_filters\": [\n")
	for i, n := range needles {
		comma := ","
		if i == len(needles)-1 {
			comma = ""
		}
		fmt.Fprintf(&dd, "    {\"name\": \"logbill-drop-%d\", \"filter\": {\"query\": \"%s\"}}%s\n", i+1, jsonEscape(n), comma)
	}
	dd.WriteString("  ]\n}")

	var vec strings.Builder
	vec.WriteString("# Drop wasteful patterns before they are indexed (Vector remap)\n")
	for _, n := range needles {
		fmt.Fprintf(&vec, "if contains(string!(.message), %q) { abort }\n", n)
	}

	var otel strings.Builder
	otel.WriteString("# OpenTelemetry Collector: filter processor (drop matching log records)\nprocessors:\n  filter/drop-waste:\n    logs:\n      log_record:\n")
	for _, n := range needles {
		fmt.Fprintf(&otel, "        - 'body contains \"%s\"'\n", n)
	}

	return Rules{Datadog: dd.String(), Vector: vec.String(), OTel: otel.String()}
}

// distinctiveFragment returns the longest literal word-run in a template,
// which is the most useful substring to match a drop rule against.
func distinctiveFragment(tmpl string) string {
	// Prefer a health/heartbeat keyword, then the longest token run.
	if m := healthRe.FindString(tmpl); m != "" {
		return m
	}
	if m := heartbeatRe.FindString(tmpl); m != "" {
		return m
	}
	best := ""
	for _, tok := range strings.Fields(tmpl) {
		if strings.Contains(tok, "<") {
			continue
		}
		if len(tok) > len(best) {
			best = tok
		}
	}
	if best == "" {
		return tmpl
	}
	return best
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// --- Output ---

func printHuman(rep *Report, topN int) {
	fmt.Printf("logbill — observability spend audit\n")
	fmt.Printf("events: %d   bytes: %d (%.2f MB)\n", rep.Events, rep.Bytes, float64(rep.Bytes)/1e6)
	fmt.Printf("wasteful: %d events (%.1f%%), %d bytes\n", rep.WasteEvents, rep.WasteShare*100, rep.WasteBytes)
	fmt.Printf("monthly cost if this is one day of volume: Datadog $%.2f  |  flat $0.50/GB $%.2f   (%s)\n\n", rep.MonthlyDatadog, rep.MonthlyFlat, rep.CostBasis)
	fmt.Printf("%-6s %-8s %-10s %s\n", "count", "share", "bytes", "pattern")
	n := topN
	if len(rep.Patterns) < n {
		n = len(rep.Patterns)
	}
	for _, p := range rep.Patterns[:n] {
		mark := ""
		if p.Waste {
			mark = "  ← " + strings.Join(p.Reasons, "; ")
		}
		fmt.Printf("%-6d %-7.1f%% %-10d %s%s\n", p.Count, p.Share*100, p.Bytes, p.Template, mark)
	}
	if len(rep.Metrics) > 0 {
		fmt.Printf("\nmetrics:\n")
		for _, m := range rep.Metrics {
			extra := ""
			if len(m.HighCard) > 0 {
				extra = "  ← high-cardinality: " + strings.Join(m.HighCard, ", ")
			}
			fmt.Printf("  %s: %d series%s\n", m.Name, m.Series, extra)
		}
	}
}

func renderMarkdown(rep *Report) string {
	var b strings.Builder
	b.WriteString("# logbill report\n\n")
	fmt.Fprintf(&b, "- Events: %d, bytes: %d\n", rep.Events, rep.Bytes)
	fmt.Fprintf(&b, "- Wasteful: %d events (%.1f%%), %d bytes\n", rep.WasteEvents, rep.WasteShare*100, rep.WasteBytes)
	fmt.Fprintf(&b, "- Monthly cost (%s): Datadog **$%.2f**, flat $0.50/GB **$%.2f**\n\n", rep.CostBasis, rep.MonthlyDatadog, rep.MonthlyFlat)
	b.WriteString("## Top patterns\n\n| Count | Share | Bytes | Pattern | Waste |\n|---:|---:|---:|---|---|\n")
	for _, p := range rep.Patterns {
		fmt.Fprintf(&b, "| %d | %.1f%% | %d | `%s` | %s |\n", p.Count, p.Share*100, p.Bytes, p.Template, strings.Join(p.Reasons, "; "))
	}
	if len(rep.Metrics) > 0 {
		b.WriteString("\n## Metrics\n\n")
		for _, m := range rep.Metrics {
			fmt.Fprintf(&b, "- `%s`: %d series", m.Name, m.Series)
			if len(m.HighCard) > 0 {
				fmt.Fprintf(&b, " — high-cardinality: %s", strings.Join(m.HighCard, ", "))
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("\n## Drop rules\n\n### Datadog exclusion filter\n\n```json\n" + rep.Rules.Datadog + "\n```\n\n### Vector remap\n\n```\n" + rep.Rules.Vector + "\n```\n\n### OpenTelemetry Collector filter processor\n\n```yaml\n" + rep.Rules.OTel + "\n```\n")
	return b.String()
}
