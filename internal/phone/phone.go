// Package phone normalises and masks Indonesian phone numbers.
package phone

import (
	"errors"
	"strings"

	"github.com/Emil-02/cekdulu/internal/score"
)

// Number is a normalised phone number.
type Number struct {
	// E164 is the canonical form, e.g. +6281234567890.
	E164     string `json:"-"`
	Masked   string `json:"masked"`
	Country  string `json:"country"`
	Type     string `json:"type"`
	Operator string `json:"operator,omitempty"`
}

// Errors returned by Parse.
var (
	ErrEmpty   = errors.New("nomor kosong")
	ErrInvalid = errors.New("format nomor tidak dikenali")
)

var operators = []struct {
	name     string
	prefixes []string
}{
	{"Telkomsel", []string{"811", "812", "813", "821", "822", "823", "851", "852", "853"}},
	{"Indosat Ooredoo", []string{"814", "815", "816", "855", "856", "857", "858"}},
	{"XL Axiata", []string{"817", "818", "819", "859", "877", "878", "879"}},
	{"Axis", []string{"831", "832", "833", "838"}},
	{"Tri (3)", []string{"895", "896", "897", "898", "899"}},
	{"Smartfren", []string{"881", "882", "883", "884", "885", "886", "887", "888", "889"}},
}

// Parse normalises s. Numbers starting with 0, 62 or +62 are Indonesian;
// other numbers must start with + and a country code.
func Parse(s string) (Number, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Number{}, ErrEmpty
	}
	plus := strings.HasPrefix(s, "+")
	var digits strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r == '+' || r == ' ' || r == '-' || r == '.' || r == '(' || r == ')':
		default:
			return Number{}, ErrInvalid
		}
	}
	d := digits.String()

	var national string
	switch {
	case strings.HasPrefix(d, "62") && (plus || len(d) >= 10):
		national = d[2:]
	case !plus && strings.HasPrefix(d, "0"):
		national = d[1:]
	case !plus && strings.HasPrefix(d, "8"):
		national = d
	case plus:
		if len(d) < 8 || len(d) > 15 {
			return Number{}, ErrInvalid
		}
		e := "+" + d
		return Number{E164: e, Masked: mask(e, 4), Country: "luar negeri", Type: "internasional"}, nil
	default:
		return Number{}, ErrInvalid
	}
	national = strings.TrimPrefix(national, "0")

	n := Number{E164: "+62" + national, Country: "ID"}
	switch {
	case strings.HasPrefix(national, "8"):
		if len(national) < 9 || len(national) > 12 {
			return Number{}, ErrInvalid
		}
		n.Type = "seluler"
		for _, op := range operators {
			for _, p := range op.prefixes {
				if strings.HasPrefix(national, p) {
					n.Operator = op.name
				}
			}
		}
	case national[0] >= '2' && national[0] <= '9':
		if len(national) < 8 || len(national) > 11 {
			return Number{}, ErrInvalid
		}
		n.Type = "telepon rumah/kantor"
	default:
		return Number{}, ErrInvalid
	}
	n.Masked = mask("0"+national, 4)
	return n, nil
}

// mask keeps the first `keep` characters and the last 3 digits.
func mask(s string, keep int) string {
	if len(s) <= keep+3 {
		return s[:min(len(s), 2)] + strings.Repeat("*", max(len(s)-2, 0))
	}
	return s[:keep] + strings.Repeat("*", len(s)-keep-3) + s[len(s)-3:]
}

// Signals returns scoring signals for the parsed number.
func Signals(n Number, err error) []score.Signal {
	if err != nil {
		return []score.Signal{{ID: "phone.invalid", Detail: err.Error()}}
	}
	if n.Country != "ID" {
		return []score.Signal{{ID: "phone.foreign", Detail: n.Masked}}
	}
	return nil
}
