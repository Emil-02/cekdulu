package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Emil-02/cekdulu/internal/blob"
	"github.com/Emil-02/cekdulu/internal/check"
	"github.com/Emil-02/cekdulu/internal/ratelimit"
	"github.com/Emil-02/cekdulu/internal/report"
	"github.com/Emil-02/cekdulu/internal/secret"
)

const modToken = "token-moderator-rahasia-123456"

var pngBytes = append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 64)...)

type testEnv struct {
	t   *testing.T
	srv *Server
}

func newEnv(t *testing.T, mod func(*Options)) *testEnv {
	t.Helper()
	h, err := secret.NewHasher(bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	store := report.NewMemory()
	svc, err := check.New(check.Config{Store: store, Hasher: h})
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{
		Service: svc, Store: store, Hasher: h,
		Blobs:      blob.Dir{Root: t.TempDir()},
		Moderators: map[string]string{modToken: "emil"},
	}
	if mod != nil {
		mod(&opt)
	}
	return &testEnv{t: t, srv: New(opt)}
}

func (e *testEnv) do(method, path string, body any, token string) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return e.serve(req)
}

func (e *testEnv) serve(req *http.Request) (int, map[string]any) {
	e.t.Helper()
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	var out map[string]any
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			e.t.Fatalf("%s %s: respons bukan JSON: %s", req.Method, req.URL, rec.Body)
		}
	}
	return rec.Code, out
}

func (e *testEnv) mustStatus(want int, method, path string, body any, token string) map[string]any {
	e.t.Helper()
	code, out := e.do(method, path, body, token)
	if code != want {
		e.t.Fatalf("%s %s = %d, ingin %d: %v", method, path, code, want, out)
	}
	return out
}

func reasons(res map[string]any) []string {
	var ids []string
	rs, _ := res["reasons"].([]any)
	for _, r := range rs {
		ids = append(ids, r.(map[string]any)["rule_id"].(string))
	}
	return ids
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

const desc = "Mengaku kurir J&T dan mengirim APK undangan lewat WhatsApp."

func TestReportModerationFlow(t *testing.T) {
	e := newEnv(t, nil)

	res := e.mustStatus(200, "POST", "/api/v1/check/phone", map[string]string{"phone": "0812-3456-7890"}, "")
	if has(reasons(res), "phone.reported") {
		t.Fatal("nomor belum pernah dilaporkan")
	}

	created := e.mustStatus(201, "POST", "/api/v1/reports", map[string]any{
		"kind": "phone", "value": "+62 812 3456 7890", "category": "impersonation",
		"description": desc, "loss_amount": 250000, "contact": "pelapor@contoh.id",
	}, "")
	id := created["id"].(string)
	if created["status"] != "pending" || strings.Contains(created["display"].(string), "3456") {
		t.Fatalf("laporan: %v", created)
	}

	st := e.mustStatus(200, "GET", "/api/v1/reports/"+id, nil, "")
	if st["status"] != "pending" {
		t.Fatalf("status publik: %v", st)
	}
	if _, ok := st["review_note"]; ok {
		t.Fatal("catatan moderator tidak boleh tampil di status publik")
	}

	// Pending reports do not affect the score yet.
	res = e.mustStatus(200, "POST", "/api/v1/check/phone", map[string]string{"phone": "081234567890"}, "")
	if has(reasons(res), "phone.reported") {
		t.Fatal("laporan pending tidak boleh memengaruhi skor")
	}

	e.mustStatus(401, "GET", "/api/v1/admin/reports", nil, "")
	e.mustStatus(401, "GET", "/api/v1/admin/reports", nil, "salah-"+modToken)

	list := e.mustStatus(200, "GET", "/api/v1/admin/reports", nil, modToken)
	reps := list["reports"].([]any)
	if len(reps) != 1 || reps[0].(map[string]any)["id"] != id {
		t.Fatalf("antrean moderasi: %v", list)
	}

	e.mustStatus(404, "POST", "/api/v1/admin/reports/"+id+"/hapus", nil, modToken)
	dec := e.mustStatus(200, "POST", "/api/v1/admin/reports/"+id+"/approve", map[string]string{"note": "bukti cukup"}, modToken)
	if dec["status"] != "approved" || dec["reviewed_by"] != "emil" {
		t.Fatalf("keputusan: %v", dec)
	}
	e.mustStatus(409, "POST", "/api/v1/admin/reports/"+id+"/reject", nil, modToken)
	e.mustStatus(404, "POST", "/api/v1/admin/reports/00000000-0000-4000-8000-000000000000/approve", nil, modToken)

	res = e.mustStatus(200, "POST", "/api/v1/check/phone", map[string]string{"phone": "081234567890"}, "")
	if !has(reasons(res), "phone.reported") || res["reported"] == nil {
		t.Fatalf("laporan disetujui harus menaikkan skor: %v", res)
	}

	stats := e.mustStatus(200, "GET", "/api/v1/stats", nil, "")
	if stats["approved_reports"].(float64) != 1 || stats["total_loss"].(float64) != 250000 {
		t.Fatalf("stats: %v", stats)
	}

	// Appeal: accepted appeals remove the indicator from results.
	e.mustStatus(404, "POST", "/api/v1/appeals", map[string]any{
		"kind": "phone", "value": "081111111111", "contact": "wa 0811", "reason": desc,
	}, "")
	ap := e.mustStatus(201, "POST", "/api/v1/appeals", map[string]any{
		"kind": "phone", "value": "081234567890", "contact": "pemilik@contoh.id",
		"reason": "Nomor ini baru saya beli bulan lalu dari operator.",
	}, "")
	apID := ap["id"].(string)
	appeals := e.mustStatus(200, "GET", "/api/v1/admin/appeals", nil, modToken)
	if len(appeals["appeals"].([]any)) != 1 {
		t.Fatalf("antrean sanggahan: %v", appeals)
	}
	e.mustStatus(200, "POST", "/api/v1/admin/appeals/"+apID+"/accept", map[string]string{"note": "terverifikasi"}, modToken)
	res = e.mustStatus(200, "POST", "/api/v1/check/phone", map[string]string{"phone": "081234567890"}, "")
	if has(reasons(res), "phone.reported") {
		t.Fatal("indikator yang sanggahannya diterima tidak boleh muncul lagi")
	}
}

func TestDomainReportAndBlocklist(t *testing.T) {
	e := newEnv(t, nil)
	created := e.mustStatus(201, "POST", "/api/v1/reports", map[string]any{
		"kind": "link", "value": "https://login.bca-hadiah.xyz/klaim", "category": "phishing", "description": desc,
	}, "")
	if created["display"] != "bca-hadiah.xyz" {
		t.Fatalf("domain: %v", created)
	}
	e.mustStatus(200, "POST", "/api/v1/admin/reports/"+created["id"].(string)+"/approve", nil, modToken)

	bl := e.mustStatus(200, "GET", "/api/v1/blocklist/domain", nil, "")
	if bl["count"].(float64) != 1 {
		t.Fatalf("blocklist: %v", bl)
	}
	req := httptest.NewRequest("GET", "/api/v1/blocklist/link?format=txt", nil)
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Body.String() != "bca-hadiah.xyz\n" {
		t.Fatalf("blocklist txt = %q", rec.Body)
	}
	e.mustStatus(404, "GET", "/api/v1/blocklist/phone", nil, "")

	res := e.mustStatus(200, "POST", "/api/v1/check/link", map[string]string{"url": "http://promo.bca-hadiah.xyz"}, "")
	if !has(reasons(res), "link.reported") || res["level"] != "bahaya" {
		t.Fatalf("cek link: %v", res)
	}
}

func TestReportValidation(t *testing.T) {
	e := newEnv(t, nil)
	cases := []map[string]any{
		{"kind": "phone", "value": "081234567890", "category": "nggak-ada", "description": desc},
		{"kind": "phone", "value": "081234567890", "category": "loan", "description": "terlalu pendek"},
		{"kind": "phone", "value": "12", "category": "loan", "description": desc},
		{"kind": "sms", "value": "081234567890", "category": "loan", "description": desc},
		{"kind": "domain", "value": "https://www.klikbca.com", "category": "phishing", "description": desc},
		{"kind": "phone", "value": "", "category": "loan", "description": desc},
		{"kind": "phone", "value": "081234567890", "category": "loan", "description": desc, "loss_amount": -5},
	}
	for _, c := range cases {
		out := e.mustStatus(400, "POST", "/api/v1/reports", c, "")
		if out["error"] == "" {
			t.Errorf("%v: pesan error kosong", c)
		}
	}
	e.mustStatus(400, "POST", "/api/v1/check/link", map[string]string{}, "")
	req := httptest.NewRequest("POST", "/api/v1/check/link", strings.NewReader(`{"url":`))
	if code, _ := e.serve(req); code != 400 {
		t.Fatalf("JSON rusak = %d", code)
	}
}

func multipartReport(t *testing.T, fields map[string]string, files map[string][]byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	for name, data := range files {
		fw, err := mw.CreateFormFile("evidence", name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(data)
	}
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/v1/reports", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func TestEvidenceUpload(t *testing.T) {
	e := newEnv(t, nil)
	fields := map[string]string{
		"kind": "account", "provider": "bca", "value": "1234567890", "category": "online_shop",
		"description": desc, "loss_amount": "500000",
	}
	code, out := e.serve(multipartReport(t, fields, map[string][]byte{"bukti.png": pngBytes}))
	if code != 201 || out["evidence"].(float64) != 1 {
		t.Fatalf("unggah bukti = %d %v", code, out)
	}
	id := out["id"].(string)

	rep := e.mustStatus(200, "GET", "/api/v1/admin/reports/"+id, nil, modToken)
	ev := rep["evidence"].([]any)[0].(map[string]any)
	if ev["mime"] != "image/png" || ev["storage_key"] != nil {
		t.Fatalf("bukti: %v", ev)
	}

	req := httptest.NewRequest("GET", "/api/v1/admin/reports/"+id+"/evidence/"+ev["id"].(string), nil)
	req.Header.Set("Authorization", "Bearer "+modToken)
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), pngBytes) || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("unduh bukti = %d %q", rec.Code, rec.Header())
	}
	req = httptest.NewRequest("GET", "/api/v1/admin/reports/"+id+"/evidence/"+ev["id"].(string), nil)
	if code, _ := e.serve(req); code != 401 {
		t.Fatalf("unduh bukti tanpa token = %d", code)
	}

	code, out = e.serve(multipartReport(t, fields, map[string][]byte{"skrip.html": []byte("<html><script>alert(1)</script>")}))
	if code != 400 {
		t.Fatalf("file HTML harus ditolak: %d %v", code, out)
	}
	code, _ = e.serve(multipartReport(t, fields, map[string][]byte{
		"1.png": pngBytes, "2.png": pngBytes, "3.png": pngBytes, "4.png": pngBytes,
	}))
	if code != 400 {
		t.Fatalf("lebih dari %d file harus ditolak: %d", MaxEvidenceFiles, code)
	}

	noBlobs := newEnv(t, func(o *Options) { o.Blobs = nil })
	if code, _ := noBlobs.serve(multipartReport(t, fields, map[string][]byte{"bukti.png": pngBytes})); code != 400 {
		t.Fatalf("unggah tanpa penyimpanan = %d", code)
	}
}

func TestRateLimitAndModerationDisabled(t *testing.T) {
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	e := newEnv(t, func(o *Options) {
		o.SubmitRate = ratelimit.Rate{N: 2, Per: time.Hour}
		o.Moderators = nil
		o.Now = func() time.Time { return now }
	})
	body := map[string]any{"kind": "domain", "value": "penipu.xyz", "category": "phishing", "description": desc}
	e.mustStatus(201, "POST", "/api/v1/reports", body, "")
	e.mustStatus(201, "POST", "/api/v1/reports", body, "")
	e.mustStatus(429, "POST", "/api/v1/reports", body, "")
	now = now.Add(time.Hour)
	e.mustStatus(201, "POST", "/api/v1/reports", body, "")

	e.mustStatus(503, "GET", "/api/v1/admin/reports", nil, modToken)
}

func TestClientIPTrustProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	if ip := (&Server{}).clientIP(req); ip != "10.0.0.1" {
		t.Fatalf("tanpa TrustProxy = %s", ip)
	}
	if ip := (&Server{opt: Options{TrustProxy: true}}).clientIP(req); ip != "203.0.113.9" {
		t.Fatalf("dengan TrustProxy = %s", ip)
	}
}

func TestParseModerators(t *testing.T) {
	m, err := ParseModerators(" emil:" + modToken + " , budi:" + strings.Repeat("b", MinTokenLen))
	if err != nil || len(m) != 2 || m[modToken] != "emil" {
		t.Fatalf("ParseModerators = %v, %v", m, err)
	}
	for _, bad := range []string{"emil", "emil:pendek", "a b:" + modToken, "a:" + modToken + ",b:" + modToken} {
		if _, err := ParseModerators(bad); err == nil {
			t.Errorf("%q harus ditolak", bad)
		}
	}
	if m, err := ParseModerators(""); err != nil || len(m) != 0 {
		t.Fatalf("kosong = %v, %v", m, err)
	}
}

func TestHealthAndPublicLists(t *testing.T) {
	e := newEnv(t, nil)
	h := e.mustStatus(200, "GET", "/health", nil, "")
	if h["status"] != "ok" || h["moderation"] != true || h["evidence"] != true {
		t.Fatalf("health: %v", h)
	}
	cats := e.mustStatus(200, "GET", "/api/v1/categories", nil, "")
	if len(cats["categories"].([]any)) != len(report.Categories) {
		t.Fatalf("kategori: %v", cats)
	}
	rules := e.mustStatus(200, "GET", "/api/v1/rules", nil, "")
	if len(rules["rules"].([]any)) == 0 {
		t.Fatal("aturan kosong")
	}
	if code, _ := e.do("GET", "/api/v1/check/link", nil, ""); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET check = %d", code)
	}
}
