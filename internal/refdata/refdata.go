// Package refdata loads reference lists (brands, shorteners, risky TLDs, ...)
// shipped in rules/data.
package refdata

import (
	"fmt"
	"io/fs"
	"strings"

	"gopkg.in/yaml.v3"
)

// Brand is an organisation commonly impersonated by scammers.
type Brand struct {
	Name     string   `yaml:"name"`
	Keywords []string `yaml:"keywords"`
	Domains  []string `yaml:"domains"`
	Packages []string `yaml:"packages"`
}

// Lists are simple reference word lists.
type Lists struct {
	Shorteners   []string `yaml:"shorteners"`
	FreeHosting  []string `yaml:"free_hosting"`
	RiskyTLDs    []string `yaml:"risky_tlds"`
	LureKeywords []string `yaml:"lure_keywords"`
	APKLures     []string `yaml:"apk_lures"`
}

// Data bundles all reference data.
type Data struct {
	Brands []Brand
	Lists
}

// Load reads data/brands.yaml and data/lists.yaml from fsys.
func Load(fsys fs.FS) (*Data, error) {
	d := &Data{}
	if err := readYAML(fsys, "data/brands.yaml", &d.Brands); err != nil {
		return nil, err
	}
	if err := readYAML(fsys, "data/lists.yaml", &d.Lists); err != nil {
		return nil, err
	}
	for i := range d.Brands {
		b := &d.Brands[i]
		b.Keywords = lower(b.Keywords)
		b.Domains = lower(b.Domains)
	}
	d.Shorteners = lower(d.Shorteners)
	d.FreeHosting = lower(d.FreeHosting)
	d.RiskyTLDs = lower(d.RiskyTLDs)
	d.LureKeywords = lower(d.LureKeywords)
	d.APKLures = lower(d.APKLures)
	return d, nil
}

// MatchesDomain reports whether host equals domain or is a subdomain of it.
func MatchesDomain(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// OfficialBrand returns the brand owning host, if any.
func (d *Data) OfficialBrand(host string) (Brand, bool) {
	for _, b := range d.Brands {
		for _, dom := range b.Domains {
			if MatchesDomain(host, dom) {
				return b, true
			}
		}
	}
	return Brand{}, false
}

func readYAML(fsys fs.FS, name string, v any) error {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	return out
}
