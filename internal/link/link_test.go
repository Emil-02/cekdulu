package link_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Emil-02/cekdulu/internal/link"
	"github.com/Emil-02/cekdulu/internal/refdata"
	"github.com/Emil-02/cekdulu/internal/score"
	"github.com/Emil-02/cekdulu/rules"
)

func data(t *testing.T) *refdata.Data {
	t.Helper()
	d, err := refdata.Load(rules.FS)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func ids(sigs []score.Signal) map[string]string {
	m := map[string]string{}
	for _, s := range sigs {
		m[s.ID] = s.Detail
	}
	return m
}

func TestStatic(t *testing.T) {
	a := link.New(data(t), link.Options{})
	cases := []struct {
		in      string
		want    []string
		notWant []string
	}{
		{"https://www.klikbca.com/login", []string{"link.official_domain"}, []string{"link.brand_lookalike", "link.lure_keywords"}},
		{"m.bca.co.id", []string{"link.official_domain"}, nil},
		{"https://klikbcca.com/login", []string{"link.brand_lookalike", "link.lure_keywords"}, nil},
		{"http://bca-verifikasi.xyz/hadiah", []string{"link.brand_in_unofficial_domain", "link.risky_tld", "link.no_https", "link.lure_keywords"}, []string{"link.official_domain"}},
		{"https://tokopedla.com", []string{"link.brand_lookalike"}, nil},
		{"https://xn--tokpedia-ui3d.com", []string{"link.punycode"}, nil},
		{"https://bit.ly/abc", []string{"link.shortener"}, nil},
		{"https://undangan-nikah.web.app/undangan.apk", []string{"link.free_hosting", "link.apk_download", "link.lure_keywords"}, nil},
		{"http://203.0.113.9/login", []string{"link.ip_host"}, nil},
		{"https://www.bri.co.id@evil.example/", []string{"link.userinfo"}, nil},
		{"https://a.b.c.d.example.com", []string{"link.many_subdomains"}, nil},
		{"https://fabric.com", nil, []string{"link.brand_in_unofficial_domain", "link.brand_lookalike"}},
		{"https://danamon.co.id", nil, []string{"link.brand_in_unofficial_domain", "link.brand_lookalike"}},
		{"https://bnn.go.id", nil, []string{"link.brand_lookalike"}},
		{"javascript:alert(1)", []string{"link.invalid_url"}, nil},
		{"halo", []string{"link.invalid_url"}, nil},
	}
	for _, c := range cases {
		_, sigs := a.Analyze(context.Background(), c.in)
		got := ids(sigs)
		for _, w := range c.want {
			if _, ok := got[w]; !ok {
				t.Errorf("%s: missing %s (got %v)", c.in, w, got)
			}
		}
		for _, w := range c.notWant {
			if _, ok := got[w]; ok {
				t.Errorf("%s: unexpected %s (got %v)", c.in, w, got)
			}
		}
	}
}

func TestCyrillicHomoglyph(t *testing.T) {
	a := link.New(data(t), link.Options{})
	// "dаnа.id" with Cyrillic а
	rep, sigs := a.Analyze(context.Background(), "https://d\u0430n\u0430.id/login")
	got := ids(sigs)
	if _, ok := got["link.brand_lookalike"]; !ok {
		t.Fatalf("expected lookalike, got %v", got)
	}
	if _, ok := got["link.punycode"]; !ok {
		t.Fatalf("expected punycode, got %v", got)
	}
	if !strings.HasPrefix(rep.Host, "xn--") {
		t.Fatalf("host should be ASCII punycode: %s", rep.Host)
	}
}

func TestBlocklist(t *testing.T) {
	a := link.New(data(t), link.Options{Blocklist: map[string]string{"evil-shop.com": "laporan 2025"}})
	_, sigs := a.Analyze(context.Background(), "https://promo.evil-shop.com/x")
	if _, ok := ids(sigs)["link.blocklisted"]; !ok {
		t.Fatal("expected blocklisted")
	}
}

func TestOnlineFollowsRedirectsAndRDAP(t *testing.T) {
	now := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/short", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://klikbcca.com/login", http.StatusFound)
	})
	mux.HandleFunc("/domain/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/redirected") {
			fmt.Fprintf(w, `{"events":[{"eventAction":"registration","eventDate":"%s"}]}`, now.AddDate(0, 0, -5).Format(time.RFC3339))
			return
		}
		http.Redirect(w, r, srv.URL+r.URL.Path+"/redirected", http.StatusFound)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// Route every request to the test server regardless of host.
	client.Transport = rewrite{base: srv.URL, rt: http.DefaultTransport}

	a := link.New(data(t), link.Options{Online: true, HTTPClient: client, RDAPBase: srv.URL, Now: func() time.Time { return now }})
	rep, sigs := a.Analyze(context.Background(), srv.URL+"/short")
	got := ids(sigs)
	for _, w := range []string{"link.redirect_offsite", "link.brand_lookalike", "link.domain_new"} {
		if _, ok := got[w]; !ok {
			t.Errorf("missing %s: %v (notes %v)", w, got, rep.Notes)
		}
	}
	if rep.FinalURL != "https://klikbcca.com/login" || rep.Domain != "klikbcca.com" {
		t.Errorf("final=%s domain=%s", rep.FinalURL, rep.Domain)
	}
	if rep.DomainCreated == nil {
		t.Error("domain created not set")
	}
}

type rewrite struct {
	base string
	rt   http.RoundTripper
}

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(req.URL.String(), r.base) {
		// External hosts (the redirect target) are answered locally with 200.
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}, Request: req}, nil
	}
	return r.rt.RoundTrip(req)
}

func TestOnlineDefaultClientBlocksPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("SSRF: private server was contacted")
	}))
	defer srv.Close()
	a := link.New(data(t), link.Options{Online: true, RDAPBase: srv.URL})
	rep, _ := a.Analyze(context.Background(), srv.URL+"/x")
	if len(rep.Notes) == 0 || !strings.Contains(strings.Join(rep.Notes, " "), "diblokir") {
		t.Fatalf("expected blocked note, got %v", rep.Notes)
	}
}
