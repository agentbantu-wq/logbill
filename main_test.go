package main

import (
	"strings"
	"testing"
)

func TestNormaliseStripsVariables(t *testing.T) {
	got := normalise(`GET /api/users/12345 from 10.0.0.7 took 42ms request_id=550e8400-e29b-41d4-a716-446655440000`)
	want := `GET /api/users/<n> from <ip> took <n>ms request_id=<uuid>`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestHealthCheckSpamFlagged(t *testing.T) {
	logs := strings.Join([]string{
		`{"level":"info","message":"GET /healthz 200"}`,
		`{"level":"info","message":"GET /healthz 200"}`,
		`{"level":"info","message":"GET /healthz 200"}`,
		`{"level":"info","message":"GET /healthz 200"}`,
		`{"level":"info","message":"GET /healthz 200"}`,
		`{"level":"info","message":"GET /healthz 200"}`,
		`{"level":"info","message":"GET /healthz 200"}`,
		`{"level":"info","message":"GET /healthz 200"}`,
		`{"level":"info","message":"GET /healthz 200"}`,
		`{"level":"info","message":"GET /healthz 200"}`,
		`{"level":"info","message":"user signed in"}`,
	}, "\n")
	rep, err := Analyze(strings.NewReader(logs), "jsonl", 10, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Events != 11 {
		t.Fatalf("events = %d, want 11", rep.Events)
	}
	if rep.WasteEvents != 10 {
		t.Fatalf("waste events = %d, want 10", rep.WasteEvents)
	}
	if len(rep.Patterns) == 0 || !rep.Patterns[0].Waste {
		t.Fatalf("top pattern should be wasteful: %+v", rep.Patterns)
	}
	if !strings.Contains(rep.Rules.Datadog, "healthz") {
		t.Fatalf("datadog rule should mention healthz: %s", rep.Rules.Datadog)
	}
}

func TestDebugInProdFlagged(t *testing.T) {
	logs := `{"level":"debug","message":"cache miss for key abc"}` + "\n" +
		`{"level":"debug","message":"cache miss for key def"}` + "\n" +
		`{"level":"info","message":"server started"}` + "\n"
	rep, err := Analyze(strings.NewReader(logs), "jsonl", 10, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range rep.Patterns {
		for _, r := range p.Reasons {
			if strings.Contains(r, "debug") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("debug pattern not flagged: %+v", rep.Patterns)
	}
}

func TestCostProjection(t *testing.T) {
	// 1 GB in a day, 1M events: Datadog = 30 * (0.10 + 1.70) = $54.00;
	// flat = 30 * 0.50 = $15.00.
	logs := strings.Repeat("x", 1000) + "\n"
	rep, err := Analyze(strings.NewReader(logs), "text", 10, 1, 1e6, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.MonthlyDatadog != 54 {
		t.Fatalf("datadog monthly = %.2f, want 54.00", rep.MonthlyDatadog)
	}
	if rep.MonthlyFlat != 15 {
		t.Fatalf("flat monthly = %.2f, want 15.00", rep.MonthlyFlat)
	}
}

func TestPrometheusHighCardinality(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 120; i++ {
		b.WriteString("http_requests_total{handler=\"/api\", user_id=\"user" + itoa(i) + "\"} 1\n")
	}
	rep, err := Analyze(strings.NewReader(b.String()), "prometheus", 10, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Metrics) != 1 || rep.Metrics[0].Series != 120 {
		t.Fatalf("metrics = %+v", rep.Metrics)
	}
	if len(rep.Metrics[0].HighCard) == 0 {
		t.Fatalf("user_id should be high-cardinality: %+v", rep.Metrics[0])
	}
	if !strings.Contains(rep.Metrics[0].HighCard[0], "user_id") {
		t.Fatalf("high-card label = %v", rep.Metrics[0].HighCard)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for i > 0 {
		d = append([]byte{byte('0' + i%10)}, d...)
		i /= 10
	}
	return string(d)
}
