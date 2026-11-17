package score_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Emil-02/cekdulu/internal/score"
	"github.com/Emil-02/cekdulu/rules"
)

func TestEmbeddedRulesLoad(t *testing.T) {
	e, err := score.LoadFS(rules.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Rules()) < 40 {
		t.Fatalf("expected many rules, got %d", len(e.Rules()))
	}
}

func TestEvaluate(t *testing.T) {
	e, err := score.New([]score.Rule{
		{ID: "a", Target: "apk", When: "x", Score: 30, Severity: "high", Message: "x {detail}"},
		{ID: "b", Target: "apk", When: "y", Score: 50, Severity: "high", Message: "y"},
		{ID: "c", Target: "apk", All: []string{"x", "y"}, Score: 40, Severity: "critical", Message: "combo"},
		{ID: "d", Target: "link", When: "x", Score: 99, Severity: "high", Message: "other target"},
		{ID: "e", Target: "apk", When: "ok", Score: -80, Severity: "info", Message: "official"},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := e.Evaluate("apk", []score.Signal{{ID: "x", Detail: "d1"}, {ID: "x", Detail: "d2"}, {ID: "y"}})
	if r.Score != 100 || r.Level != score.LevelDanger {
		t.Fatalf("score=%d level=%s", r.Score, r.Level)
	}
	if len(r.Reasons) != 3 || r.Reasons[0].RuleID != "b" {
		t.Fatalf("reasons not sorted by score: %+v", r.Reasons)
	}
	for _, rs := range r.Reasons {
		if rs.RuleID == "a" && rs.Message != "x d1, d2" {
			t.Fatalf("detail substitution: %q", rs.Message)
		}
	}

	r = e.Evaluate("apk", []score.Signal{{ID: "x"}, {ID: "ok"}})
	if r.Score != 0 || r.Level != score.LevelLow {
		t.Fatalf("negative clamp: %+v", r)
	}
	r = e.Evaluate("apk", []score.Signal{{ID: "x"}})
	if r.Level != score.LevelWarning {
		t.Fatalf("want warning, got %s", r.Level)
	}
}

func TestNewValidates(t *testing.T) {
	cases := map[string]score.Rule{
		"missing id":  {Target: "apk", When: "x", Severity: "low", Message: "m"},
		"bad target":  {ID: "a", Target: "foo", When: "x", Severity: "low", Message: "m"},
		"both":        {ID: "a", Target: "apk", When: "x", All: []string{"y"}, Severity: "low", Message: "m"},
		"neither":     {ID: "a", Target: "apk", Severity: "low", Message: "m"},
		"bad sev":     {ID: "a", Target: "apk", When: "x", Severity: "meh", Message: "m"},
		"no message":  {ID: "a", Target: "apk", When: "x", Severity: "low"},
		"score range": {ID: "a", Target: "apk", When: "x", Severity: "low", Message: "m", Score: 101},
	}
	for name, r := range cases {
		if _, err := score.New([]score.Rule{r}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	dup := score.Rule{ID: "a", Target: "apk", When: "x", Severity: "low", Message: "m"}
	if _, err := score.New([]score.Rule{dup, dup}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate: %v", err)
	}
}

func TestLoadFSRejectsBadYAML(t *testing.T) {
	fsys := fstest.MapFS{"r/x.yaml": {Data: []byte("- id: [")}}
	if _, err := score.LoadFS(fsys, "r"); err == nil {
		t.Fatal("expected error")
	}
}
