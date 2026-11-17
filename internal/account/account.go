// Package account normalises bank accounts and e-wallet IDs.
package account

import (
	"errors"
	"sort"
	"strings"

	"github.com/Emil-02/cekdulu/internal/phone"
)

// Provider is a bank or e-wallet.
type Provider struct {
	Code    string `json:"code"`
	Name    string `json:"name"`
	EWallet bool   `json:"ewallet"`
}

// Providers lists supported banks and e-wallets.
var Providers = []Provider{
	{"bca", "BCA", false}, {"bri", "BRI", false}, {"bni", "BNI", false}, {"mandiri", "Bank Mandiri", false},
	{"bsi", "BSI", false}, {"btn", "BTN", false}, {"cimb", "CIMB Niaga", false}, {"permata", "Bank Permata", false},
	{"danamon", "Bank Danamon", false}, {"ocbc", "OCBC", false}, {"panin", "Panin Bank", false},
	{"maybank", "Maybank Indonesia", false}, {"btpn", "SMBC Indonesia / Jenius", false}, {"jago", "Bank Jago", false},
	{"seabank", "SeaBank", false}, {"blu", "blu by BCA Digital", false}, {"neo", "Bank Neo Commerce", false},
	{"bpd", "Bank Pembangunan Daerah", false}, {"lain", "Bank lainnya", false},
	{"dana", "DANA", true}, {"ovo", "OVO", true}, {"gopay", "GoPay", true}, {"shopeepay", "ShopeePay", true},
	{"linkaja", "LinkAja", true},
}

// Account is a normalised account.
type Account struct {
	Provider Provider `json:"provider"`
	// Canonical is the value hashed for storage, e.g. "bank:bca:1234567890".
	Canonical string `json:"-"`
	Masked    string `json:"masked"`
}

// Errors returned by Parse.
var (
	ErrProvider = errors.New("bank/e-wallet tidak dikenali")
	ErrNumber   = errors.New("nomor rekening tidak valid")
)

// Lookup returns the provider for code (case-insensitive).
func Lookup(code string) (Provider, bool) {
	code = strings.ToLower(strings.TrimSpace(code))
	for _, p := range Providers {
		if p.Code == code {
			return p, true
		}
	}
	return Provider{}, false
}

// Codes returns all provider codes, sorted.
func Codes() []string {
	out := make([]string, len(Providers))
	for i, p := range Providers {
		out[i] = p.Code
	}
	sort.Strings(out)
	return out
}

// Parse validates and normalises an account.
func Parse(providerCode, number string) (Account, error) {
	p, ok := Lookup(providerCode)
	if !ok {
		return Account{}, ErrProvider
	}
	if p.EWallet {
		n, err := phone.Parse(number)
		if err != nil || n.Country != "ID" || n.Type != "seluler" {
			return Account{}, ErrNumber
		}
		return Account{Provider: p, Canonical: "ewallet:" + p.Code + ":" + n.E164, Masked: p.Name + " " + n.Masked}, nil
	}
	var d strings.Builder
	for _, r := range number {
		switch {
		case r >= '0' && r <= '9':
			d.WriteRune(r)
		case r == ' ' || r == '-' || r == '.':
		default:
			return Account{}, ErrNumber
		}
	}
	digits := d.String()
	if len(digits) < 6 || len(digits) > 20 {
		return Account{}, ErrNumber
	}
	masked := strings.Repeat("*", len(digits)-4) + digits[len(digits)-4:]
	return Account{Provider: p, Canonical: "bank:" + p.Code + ":" + digits, Masked: p.Name + " " + masked}, nil
}
