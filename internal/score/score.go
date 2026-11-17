// Package score turns signals emitted by the analyzers into an explainable
// 0-100 risk score using community-maintained YAML rules.
package score

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Targets an analyzer can produce signals for.
const (
	TargetLink    = "link"
	TargetAPK     = "apk"
	TargetPhone   = "phone"
	TargetAccount = "account"
)

// Risk levels, from least to most dangerous.
const (
	LevelLow     = "rendah"
	LevelWarning = "waspada"
	LevelDanger  = "bahaya"
)

// Signal is a single fact found by an analyzer, e.g. "apk.perm.READ_SMS".
type Signal struct {
	ID     string `json:"id"`
	Detail string `json:"detail,omitempty"`
}

// Rule maps one signal (When) or a combination of signals (All) to a score.
type Rule struct {
	ID       string   `yaml:"id" json:"id"`
	Target   string   `yaml:"target" json:"target"`
	When     string   `yaml:"when,omitempty" json:"when,omitempty"`
	All      []string `yaml:"all,omitempty" json:"all,omitempty"`
	Score    int      `yaml:"score" json:"score"`
	Severity string   `yaml:"severity" json:"severity"`
	Message  string   `yaml:"message" json:"message"`
	Advice   string   `yaml:"advice,omitempty" json:"advice,omitempty"`
}

// Reason explains why points were added to (or removed from) the score.
type Reason struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Score    int    `json:"score"`
	Message  string `json:"message"`
	Advice   string `json:"advice,omitempty"`
}

// Result is the explainable verdict for one checked item.
type Result struct {
	Score   int      `json:"score"`
	Level   string   `json:"level"`
	Reasons []Reason `json:"reasons"`
}

// Engine evaluates rules. It is safe for concurrent use after construction.
type Engine struct {
	rules []Rule
}

var validSeverity = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}

var validTarget = map[string]bool{TargetLink: true, TargetAPK: true, TargetPhone: true, TargetAccount: true}

// New validates rules and returns an engine.
func New(rules []Rule) (*Engine, error) {
	seen := map[string]bool{}
	for i, r := range rules {
		switch {
		case r.ID == "":
			return nil, fmt.Errorf("rule #%d: id is required", i+1)
		case seen[r.ID]:
			return nil, fmt.Errorf("rule %s: duplicate id", r.ID)
		case !validTarget[r.Target]:
			return nil, fmt.Errorf("rule %s: unknown target %q", r.ID, r.Target)
		case (r.When == "") == (len(r.All) == 0):
			return nil, fmt.Errorf("rule %s: set exactly one of when or all", r.ID)
		case !validSeverity[r.Severity]:
			return nil, fmt.Errorf("rule %s: unknown severity %q", r.ID, r.Severity)
		case strings.TrimSpace(r.Message) == "":
			return nil, fmt.Errorf("rule %s: message is required", r.ID)
		case r.Score < -100 || r.Score > 100:
			return nil, fmt.Errorf("rule %s: score must be between -100 and 100", r.ID)
		}
		seen[r.ID] = true
	}
	return &Engine{rules: rules}, nil
}

// LoadFS reads every *.yaml / *.yml file in dir of fsys.
func LoadFS(fsys fs.FS, dir string) (*Engine, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var all []Rule
	for _, e := range entries {
		ext := path.Ext(e.Name())
		if e.IsDir() || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var rs []Rule
		if err := yaml.Unmarshal(b, &rs); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		all = append(all, rs...)
	}
	return New(all)
}

// Rules returns a copy of the loaded rules.
func (e *Engine) Rules() []Rule {
	return append([]Rule(nil), e.rules...)
}

// Evaluate scores the signals for target.
func (e *Engine) Evaluate(target string, signals []Signal) Result {
	details := map[string][]string{}
	for _, s := range signals {
		details[s.ID] = append(details[s.ID], s.Detail)
	}

	res := Result{Reasons: []Reason{}}
	total := 0
	for _, r := range e.rules {
		if r.Target != target {
			continue
		}
		var detail string
		if r.When != "" {
			d, ok := details[r.When]
			if !ok {
				continue
			}
			detail = joinDetails(d)
		} else {
			matched := true
			var parts []string
			for _, id := range r.All {
				d, ok := details[id]
				if !ok {
					matched = false
					break
				}
				parts = append(parts, d...)
			}
			if !matched {
				continue
			}
			detail = joinDetails(parts)
		}
		total += r.Score
		res.Reasons = append(res.Reasons, Reason{
			RuleID:   r.ID,
			Severity: r.Severity,
			Score:    r.Score,
			Message:  strings.ReplaceAll(strings.TrimSpace(r.Message), "{detail}", detail),
			Advice:   strings.TrimSpace(r.Advice),
		})
	}

	res.Score = min(max(total, 0), 100)
	res.Level = Level(res.Score)
	sort.SliceStable(res.Reasons, func(i, j int) bool { return res.Reasons[i].Score > res.Reasons[j].Score })
	return res
}

// Level converts a score into a human-readable level.
func Level(score int) string {
	switch {
	case score >= 60:
		return LevelDanger
	case score >= 25:
		return LevelWarning
	default:
		return LevelLow
	}
}

func joinDetails(ds []string) string {
	var out []string
	seen := map[string]bool{}
	for _, d := range ds {
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return strings.Join(out, ", ")
}
