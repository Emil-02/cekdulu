// Package link analyses URLs for phishing and scam indicators.
//
// Static checks (lookalike domains, punycode, risky TLDs, ...) never touch
// the network. When Options.Online is set, the analyzer also follows
// redirects (to reveal shortened links) and queries RDAP for the domain
// registration date, using an SSRF-safe HTTP client.
package link

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/Emil-02/cekdulu/internal/netsafe"
	"github.com/Emil-02/cekdulu/internal/refdata"
	"github.com/Emil-02/cekdulu/internal/score"
)

// Options configure the analyzer.
type Options struct {
	// Online enables redirect following and RDAP lookups.
	Online bool
	// HTTPClient is used for online checks. It must not follow redirects.
	// Defaults to an SSRF-safe client.
	HTTPClient *http.Client
	// RDAPBase is the RDAP bootstrap service. Defaults to https://rdap.org.
	RDAPBase string
	// MaxRedirects limits redirect hops. Defaults to 10.
	MaxRedirects int
	// Now returns the current time (for tests).
	Now func() time.Time
	// Blocklist contains registrable domains known to be malicious.
	Blocklist map[string]string
}

// Report holds the facts collected about a URL.
type Report struct {
	Input         string     `json:"input"`
	URL           string     `json:"url,omitempty"`
	Host          string     `json:"host,omitempty"`
	UnicodeHost   string     `json:"unicode_host,omitempty"`
	Domain        string     `json:"domain,omitempty"`
	FinalURL      string     `json:"final_url,omitempty"`
	Redirects     []string   `json:"redirects,omitempty"`
	DomainCreated *time.Time `json:"domain_created,omitempty"`
	Notes         []string   `json:"notes,omitempty"`
}

// Analyzer checks URLs. It is safe for concurrent use.
type Analyzer struct {
	data *refdata.Data
	opt  Options
}

// New returns an analyzer.
func New(data *refdata.Data, opt Options) *Analyzer {
	if opt.HTTPClient == nil {
		opt.HTTPClient = netsafe.Client(8 * time.Second)
	}
	if opt.RDAPBase == "" {
		opt.RDAPBase = "https://rdap.org"
	}
	if opt.MaxRedirects == 0 {
		opt.MaxRedirects = 10
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Analyzer{data: data, opt: opt}
}

// Analyze inspects raw and returns a report plus the signals for scoring.
func (a *Analyzer) Analyze(ctx context.Context, raw string) (Report, []score.Signal) {
	rep := Report{Input: raw}
	u, err := Normalize(raw)
	if err != nil {
		return rep, []score.Signal{{ID: "link.invalid_url", Detail: err.Error()}}
	}
	rep.URL = u.String()
	sigs := a.static(u, &rep)

	if !a.opt.Online {
		return rep, sigs
	}

	final, hops, err := a.follow(ctx, u)
	rep.Redirects = hops
	if err != nil {
		rep.Notes = append(rep.Notes, "gagal mengikuti tautan: "+err.Error())
	}
	if final != nil && final.String() != u.String() {
		rep.FinalURL = final.String()
		finalDomain := registrable(hostname(final))
		if finalDomain != rep.Domain {
			sigs = append(sigs, score.Signal{ID: "link.redirect_offsite", Detail: finalDomain})
			var finalRep Report
			for _, s := range a.static(final, &finalRep) {
				if s.ID != "link.shortener" {
					sigs = append(sigs, s)
				}
			}
			rep.Domain = finalDomain
		}
	}

	if rep.Domain != "" && !hasSignal(sigs, "link.official_domain") {
		created, err := a.registrationDate(ctx, rep.Domain)
		switch {
		case err != nil:
			rep.Notes = append(rep.Notes, "umur domain tidak diketahui: "+err.Error())
		default:
			rep.DomainCreated = &created
			days := int(a.opt.Now().Sub(created).Hours() / 24)
			switch {
			case days < 30:
				sigs = append(sigs, score.Signal{ID: "link.domain_new", Detail: fmt.Sprintf("%d hari lalu", days)})
			case days < 180:
				sigs = append(sigs, score.Signal{ID: "link.domain_young", Detail: fmt.Sprintf("%d hari", days)})
			}
		}
	}
	return rep, dedupe(sigs)
}

// Normalize parses user input into an absolute http(s) URL. Input without a
// scheme is treated as https.
func Normalize(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, "<>\"'()[]")
	if s == "" {
		return nil, fmt.Errorf("kosong")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("format tidak dikenali")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("skema %q tidak didukung", u.Scheme)
	}
	host := hostname(u)
	if host == "" {
		return nil, fmt.Errorf("tidak ada nama domain")
	}
	if net.ParseIP(host) == nil && !strings.Contains(host, ".") {
		return nil, fmt.Errorf("nama domain %q tidak lengkap", host)
	}
	return u, nil
}

func (a *Analyzer) static(u *url.URL, rep *Report) []score.Signal {
	var sigs []score.Signal
	add := func(id, detail string) { sigs = append(sigs, score.Signal{ID: id, Detail: detail}) }

	host := hostname(u)
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		ascii = host
	}
	uni, _ := idna.Display.ToUnicode(ascii)
	rep.Host = ascii
	if uni != ascii {
		rep.UnicodeHost = uni
	}

	if u.Scheme == "http" {
		add("link.no_https", "")
	}
	if u.User != nil {
		add("link.userinfo", ascii)
	}
	if strings.HasSuffix(strings.ToLower(u.EscapedPath()), ".apk") {
		add("link.apk_download", "")
	}

	if ip := net.ParseIP(strings.Trim(ascii, "[]")); ip != nil {
		add("link.ip_host", ip.String())
		rep.Domain = ip.String()
		return sigs
	}

	domain := registrable(ascii)
	rep.Domain = domain

	if reason, ok := a.opt.Blocklist[domain]; ok {
		add("link.blocklisted", reason)
	}

	if brand, ok := a.data.OfficialBrand(ascii); ok {
		add("link.official_domain", domain+" ("+brand.Name+")")
		return sigs
	}

	if strings.Contains(ascii, "xn--") {
		add("link.punycode", uni)
	}
	if scripts := mixedScripts(uni); scripts != "" {
		add("link.mixed_script", scripts)
	}

	for _, s := range a.data.Shorteners {
		if refdata.MatchesDomain(ascii, s) {
			add("link.shortener", s)
		}
	}
	for _, f := range a.data.FreeHosting {
		if refdata.MatchesDomain(ascii, f) {
			add("link.free_hosting", f)
		}
	}
	suffix, _ := publicsuffix.PublicSuffix(ascii)
	for _, t := range a.data.RiskyTLDs {
		if suffix == t || strings.HasSuffix(suffix, "."+t) {
			add("link.risky_tld", t)
			break
		}
	}
	if sub := strings.TrimSuffix(ascii, domain); sub != ascii && strings.Count(sub, ".") >= 3 {
		add("link.many_subdomains", fmt.Sprintf("%d", strings.Count(sub, ".")))
	}

	if brand, official, ok := a.lookalike(domain, uni); ok {
		add("link.brand_lookalike", fmt.Sprintf("mirip %s milik %s", official, brand))
	} else if name, ok := a.brandInHost(ascii); ok {
		add("link.brand_in_unofficial_domain", name)
	}

	if lures := a.lures(ascii + "/" + u.Path + "?" + u.RawQuery); len(lures) > 0 {
		add("link.lure_keywords", strings.Join(lures, ", "))
	}
	return sigs
}

// lookalike compares the registrable label with official brand domains,
// using homoglyph skeletons and edit distance.
func (a *Analyzer) lookalike(domain, unicodeHost string) (brand, official string, ok bool) {
	label := firstLabel(domain)
	uniLabel := firstLabel(registrableUnicode(unicodeHost, domain))
	cand := skeleton(label)
	candUni := skeleton(uniLabel)
	for _, b := range a.data.Brands {
		for _, d := range b.Domains {
			ol := firstLabel(registrable(d))
			if ol == label || len(ol) < 3 {
				continue
			}
			os := skeleton(ol)
			if cand == os || candUni == os {
				return b.Name, d, true
			}
			dist := distance(cand, os)
			if (len(ol) >= 5 && dist == 1) || (len(ol) >= 9 && dist == 2) {
				return b.Name, d, true
			}
		}
	}
	return "", "", false
}

func (a *Analyzer) brandInHost(host string) (string, bool) {
	tokens := tokenize(host)
	for _, b := range a.data.Brands {
		for _, kw := range b.Keywords {
			for _, t := range tokens {
				if t == kw || (len(kw) >= 5 && strings.Contains(t, kw)) {
					return b.Name, true
				}
			}
		}
	}
	return "", false
}

func (a *Analyzer) lures(s string) []string {
	var found []string
	tokens := tokenize(s)
	for _, kw := range a.data.LureKeywords {
		for _, t := range tokens {
			if t == kw || (len(kw) >= 5 && strings.Contains(t, kw)) {
				found = append(found, kw)
				break
			}
		}
	}
	return found
}

func (a *Analyzer) follow(ctx context.Context, u *url.URL) (*url.URL, []string, error) {
	cur := u
	var hops []string
	for i := 0; i <= a.opt.MaxRedirects; i++ {
		next, err := a.hop(ctx, cur)
		if err != nil {
			return cur, hops, err
		}
		if next == nil {
			return cur, hops, nil
		}
		hops = append(hops, next.String())
		cur = next
	}
	return cur, hops, fmt.Errorf("terlalu banyak pengalihan")
}

func (a *Analyzer) hop(ctx context.Context, u *url.URL) (*url.URL, error) {
	resp, err := a.request(ctx, http.MethodHead, u)
	if err == nil && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented) {
		resp, err = a.request(ctx, http.MethodGet, u)
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return nil, nil
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, nil
	}
	next, err := u.Parse(loc)
	if err != nil {
		return nil, fmt.Errorf("pengalihan tidak valid")
	}
	if next.Scheme != "http" && next.Scheme != "https" {
		return nil, fmt.Errorf("pengalihan ke skema %q", next.Scheme)
	}
	return next, nil
}

func (a *Analyzer) request(ctx context.Context, method string, u *url.URL) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; cekdulu/1.0; +https://github.com/Emil-02/cekdulu)")
	resp, err := a.opt.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	return resp, nil
}

// registrationDate queries RDAP, following its redirects manually so the
// SSRF guard applies to every hop.
func (a *Analyzer) registrationDate(ctx context.Context, domain string) (time.Time, error) {
	target := strings.TrimRight(a.opt.RDAPBase, "/") + "/domain/" + url.PathEscape(domain)
	for range 5 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return time.Time{}, err
		}
		req.Header.Set("Accept", "application/rdap+json, application/json")
		resp, err := a.opt.HTTPClient.Do(req)
		if err != nil {
			return time.Time{}, err
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			_ = resp.Body.Close()
			loc, err := resp.Request.URL.Parse(resp.Header.Get("Location"))
			if err != nil || loc.Scheme != "https" && loc.Scheme != "http" {
				return time.Time{}, fmt.Errorf("pengalihan RDAP tidak valid")
			}
			target = loc.String()
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return time.Time{}, fmt.Errorf("RDAP status %d", resp.StatusCode)
		}
		var body struct {
			Events []struct {
				Action string `json:"eventAction"`
				Date   string `json:"eventDate"`
			} `json:"events"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
			return time.Time{}, fmt.Errorf("respons RDAP tidak valid")
		}
		for _, e := range body.Events {
			if e.Action == "registration" {
				return time.Parse(time.RFC3339, e.Date)
			}
		}
		return time.Time{}, fmt.Errorf("tanggal registrasi tidak tersedia")
	}
	return time.Time{}, fmt.Errorf("terlalu banyak pengalihan RDAP")
}

func hostname(u *url.URL) string {
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

func registrable(host string) string {
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return d
}

func registrableUnicode(uniHost, asciiDomain string) string {
	n := strings.Count(asciiDomain, ".") + 1
	labels := strings.Split(uniHost, ".")
	if len(labels) < n {
		return uniHost
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

func firstLabel(domain string) string {
	if i := strings.IndexByte(domain, '.'); i >= 0 {
		return domain[:i]
	}
	return domain
}

func tokenize(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

var confusables = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'l', 'ј': 'j',
	'ԁ': 'd', 'ɡ': 'g', 'ӏ': 'l', 'ѕ': 's', 'һ': 'h', 'к': 'k', 'м': 'm', 'т': 't', 'в': 'b', 'н': 'h',
	'ο': 'o', 'α': 'a', 'ν': 'v', 'ρ': 'p', 'ι': 'l', 'κ': 'k', 'τ': 't', 'υ': 'u',
	'0': 'o', '1': 'l', 'i': 'l', '3': 'e', '5': 's', '@': 'a', '$': 's',
}

// skeleton maps visually similar characters to a canonical form.
func skeleton(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if c, ok := confusables[r]; ok {
			r = c
		}
		if r == '-' {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	out = strings.ReplaceAll(out, "rn", "m")
	out = strings.ReplaceAll(out, "vv", "w")
	return out
}

// distance is the optimal string alignment (Damerau-Levenshtein) distance.
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}

func mixedScripts(host string) string {
	for _, label := range strings.Split(host, ".") {
		scripts := map[string]bool{}
		for _, r := range label {
			switch {
			case unicode.Is(unicode.Latin, r):
				scripts["Latin"] = true
			case unicode.Is(unicode.Cyrillic, r):
				scripts["Sirilik"] = true
			case unicode.Is(unicode.Greek, r):
				scripts["Yunani"] = true
			case unicode.IsLetter(r):
				scripts["lainnya"] = true
			}
		}
		if len(scripts) > 1 {
			var names []string
			for _, n := range []string{"Latin", "Sirilik", "Yunani", "lainnya"} {
				if scripts[n] {
					names = append(names, n)
				}
			}
			return strings.Join(names, " + ")
		}
	}
	return ""
}

func hasSignal(sigs []score.Signal, id string) bool {
	for _, s := range sigs {
		if s.ID == id {
			return true
		}
	}
	return false
}

func dedupe(sigs []score.Signal) []score.Signal {
	seen := map[score.Signal]bool{}
	out := sigs[:0]
	for _, s := range sigs {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
