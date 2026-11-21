package telegram

import (
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/Emil-02/cekdulu/internal/account"
	"github.com/Emil-02/cekdulu/internal/link"
	"github.com/Emil-02/cekdulu/internal/phone"
)

// Item kinds found in a message.
const (
	ItemLink    = "link"
	ItemPhone   = "phone"
	ItemAccount = "account"
)

// MaxItems caps how many indicators are checked per message.
const MaxItems = 5

// Item is something worth checking that was found in a message.
type Item struct {
	Kind     string
	Value    string
	Provider string
}

var (
	urlRe   = regexp.MustCompile(`(?i)\b(?:https?://|www\.)[^\s<>"']+`)
	phoneRe = regexp.MustCompile(`(?:\+\s?62|\b62|\b0)[\s\-.]?8\d(?:[\s\-.]?\d){6,11}\b`)
	// Bank or e-wallet name, up to 25 non-digit characters (e.g. "no rek:"),
	// then the number.
	accountRe = regexp.MustCompile(`(?i)\b(` + strings.Join(accountNames(), "|") +
		`)\b[^\d\n]{0,25}?(\+?\d[\d \-.]{4,24}\d)`)
)

var providerAlias = map[string]string{"jenius": "btpn", "blu": "blu", "sea": "seabank"}

func accountNames() []string {
	var out []string
	for _, c := range account.Codes() {
		if c == "lain" || c == "bpd" {
			continue
		}
		out = append(out, c)
	}
	for a := range providerAlias {
		if _, ok := account.Lookup(a); !ok {
			out = append(out, a)
		}
	}
	return out
}

// utf16Slice returns text[offset:offset+length] where offsets are UTF-16
// code units, as Telegram reports them.
func utf16Slice(text string, offset, length int) string {
	u := utf16.Encode([]rune(text))
	if offset < 0 || length <= 0 || offset+length > len(u) {
		return ""
	}
	return string(utf16.Decode(u[offset : offset+length]))
}

// Extract finds links, phone numbers and bank/e-wallet accounts in text.
// Telegram entities are used first; regular expressions catch the rest.
func Extract(text string, entities []Entity) []Item {
	var out []Item
	seen := map[string]bool{}
	add := func(it Item) {
		key, ok := canonical(it)
		if !ok || seen[key] || len(out) >= MaxItems {
			return
		}
		seen[key] = true
		out = append(out, it)
	}

	for _, e := range entities {
		switch e.Type {
		case "url":
			add(Item{Kind: ItemLink, Value: utf16Slice(text, e.Offset, e.Length)})
		case "text_link":
			add(Item{Kind: ItemLink, Value: e.URL})
		case "phone_number":
			add(Item{Kind: ItemPhone, Value: utf16Slice(text, e.Offset, e.Length)})
		}
	}
	for _, m := range urlRe.FindAllString(text, -1) {
		add(Item{Kind: ItemLink, Value: strings.TrimRight(m, ".,;:!?)]}")})
	}
	for _, m := range accountRe.FindAllStringSubmatch(text, -1) {
		code := strings.ToLower(m[1])
		if a, ok := providerAlias[code]; ok {
			code = a
		}
		add(Item{Kind: ItemAccount, Provider: code, Value: strings.TrimSpace(m[2])})
	}
	for _, m := range phoneRe.FindAllString(text, -1) {
		add(Item{Kind: ItemPhone, Value: m})
	}
	return out
}

// canonical validates an item and returns a dedup key.
func canonical(it Item) (string, bool) {
	switch it.Kind {
	case ItemLink:
		u, err := link.Normalize(it.Value)
		if err != nil {
			return "", false
		}
		return "link:" + strings.ToLower(u.Host) + u.RequestURI(), true
	case ItemPhone:
		n, err := phone.Parse(it.Value)
		if err != nil {
			return "", false
		}
		return "phone:" + n.E164, true
	case ItemAccount:
		a, err := account.Parse(it.Provider, it.Value)
		if err != nil {
			return "", false
		}
		return "account:" + a.Canonical, true
	}
	return "", false
}
