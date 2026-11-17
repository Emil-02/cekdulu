package apk_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Emil-02/cekdulu/internal/apk"
	"github.com/Emil-02/cekdulu/internal/apk/apktest"
	"github.com/Emil-02/cekdulu/internal/refdata"
	"github.com/Emil-02/cekdulu/internal/score"
	"github.com/Emil-02/cekdulu/rules"
)

var now = time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)

func analyzer(t *testing.T, opt apk.Options) *apk.Analyzer {
	t.Helper()
	d, err := refdata.Load(rules.FS)
	if err != nil {
		t.Fatal(err)
	}
	opt.Now = func() time.Time { return now }
	return apk.New(d, opt)
}

func ids(sigs []score.Signal) map[string]string {
	m := map[string]string{}
	for _, s := range sigs {
		m[s.ID] = s.Detail
	}
	return m
}

// ScamSpec mimics the "undangan pernikahan" SMS-stealer APKs.
var scamSpec = apktest.Spec{
	Package:          "com.example.myapplication",
	Label:            "Undangan Pernikahan",
	LabelInResources: true,
	MinSDK:           21,
	TargetSDK:        22,
	Permissions: []string{
		"android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.SEND_SMS",
		"android.permission.INTERNET", "android.permission.READ_CONTACTS",
	},
	Services:   []apktest.Component{{Name: ".Acc", Permission: "android.permission.BIND_ACCESSIBILITY_SERVICE"}},
	Receivers:  []apktest.Component{{Name: ".SmsReceiver", Actions: []string{"android.provider.Telephony.SMS_RECEIVED"}}},
	DexStrings: []string{"https://api.telegram.org/bot1234567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ/sendMessage", "https://panel-undangan.xyz/api"},
	CertCN:     "Android Debug",
	V2:         true,
}

func TestScamAPK(t *testing.T) {
	b := apktest.Build(scamSpec)
	a := analyzer(t, apk.Options{})
	rep, sigs, err := a.Analyze(bytes.NewReader(b), int64(len(b)), "Undangan_Pernikahan.apk")
	if err != nil {
		t.Fatal(err)
	}
	got := ids(sigs)
	for _, w := range []string{
		"apk.perm.READ_SMS", "apk.perm.RECEIVE_SMS", "apk.perm.SEND_SMS", "apk.receiver.sms",
		"apk.service.accessibility", "apk.telegram_bot", "apk.lure_name", "apk.cert.debug",
		"apk.target_sdk_old", "apk.package.generic",
	} {
		if _, ok := got[w]; !ok {
			t.Errorf("missing %s; got %v", w, got)
		}
	}
	if rep.Package != "com.example.myapplication" || rep.Label != "Undangan Pernikahan" || rep.TargetSDK != 22 || rep.MinSDK != 21 {
		t.Errorf("manifest: %+v", rep)
	}
	if strings.Contains(got["apk.telegram_bot"], "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ") || !strings.Contains(got["apk.telegram_bot"], "1234567890") {
		t.Errorf("telegram token must be masked: %q", got["apk.telegram_bot"])
	}
	if len(rep.Hosts) != 1 || rep.Hosts[0] != "panel-undangan.xyz" {
		t.Errorf("hosts: %v", rep.Hosts)
	}
	if len(rep.Certificates) != 1 || !rep.Certificates[0].Debug {
		t.Errorf("certs (v1+v2 must dedupe): %+v", rep.Certificates)
	}
	if strings.Join(rep.SigningSchemes, ",") != "v1,v2" {
		t.Errorf("schemes: %v", rep.SigningSchemes)
	}
	if len(rep.SHA256) != 64 {
		t.Error("sha256 missing")
	}

	e, _ := score.LoadFS(rules.FS, ".")
	res := e.Evaluate(score.TargetAPK, sigs)
	if res.Score != 100 || res.Level != score.LevelDanger {
		t.Errorf("scam APK should be max danger: %+v", res)
	}
}

func TestBenignAPK(t *testing.T) {
	b := apktest.Build(apktest.Spec{
		Package: "id.go.kalkulator", Label: "Kalkulator Zakat", MinSDK: 24, TargetSDK: 34, VersionName: "1.2.0",
		Permissions:   []string{"android.permission.INTERNET"},
		CertCN:        "Kalkulator Zakat Release",
		CertNotBefore: now.AddDate(-2, 0, 0),
	})
	rep, sigs, err := analyzer(t, apk.Options{}).Analyze(bytes.NewReader(b), int64(len(b)), "zakat.apk")
	if err != nil {
		t.Fatal(err)
	}
	e, _ := score.LoadFS(rules.FS, ".")
	res := e.Evaluate(score.TargetAPK, sigs)
	if res.Score != 0 {
		t.Errorf("benign APK scored %d: %+v", res.Score, res.Reasons)
	}
	if rep.Label != "Kalkulator Zakat" || rep.VersionName != "1.2.0" {
		t.Errorf("%+v", rep)
	}
}

func TestBrandImpersonation(t *testing.T) {
	b := apktest.Build(apktest.Spec{Package: "com.bcamobile.update", Label: "BCA Mobile Update", TargetSDK: 34, CertCN: "x"})
	_, sigs, _ := analyzer(t, apk.Options{}).Analyze(bytes.NewReader(b), int64(len(b)), "a.apk")
	if ids(sigs)["apk.brand_impersonation"] != "BCA" {
		t.Errorf("got %v", ids(sigs))
	}
	b = apktest.Build(apktest.Spec{Package: "com.bca.mybca.omni.android", Label: "myBCA", TargetSDK: 34, CertCN: "x"})
	_, sigs, _ = analyzer(t, apk.Options{}).Analyze(bytes.NewReader(b), int64(len(b)), "a.apk")
	if _, ok := ids(sigs)["apk.brand_impersonation"]; ok {
		t.Error("official package flagged")
	}
}

func TestUnsignedRecentAndBlocklist(t *testing.T) {
	b := apktest.Build(apktest.Spec{Package: "a.b.c", TargetSDK: 34})
	rep, sigs, _ := analyzer(t, apk.Options{}).Analyze(bytes.NewReader(b), int64(len(b)), "x.apk")
	if _, ok := ids(sigs)["apk.cert.missing"]; !ok {
		t.Error("unsigned not detected")
	}
	b2 := apktest.Build(apktest.Spec{Package: "a.b.c", TargetSDK: 34, CertCN: "n", CertNotBefore: now.AddDate(0, 0, -3)})
	_, sigs, _ = analyzer(t, apk.Options{}).Analyze(bytes.NewReader(b2), int64(len(b2)), "x.apk")
	if ids(sigs)["apk.cert.recent"] != "3 hari lalu" {
		t.Errorf("recent cert: %v", ids(sigs))
	}
	_, sigs, _ = analyzer(t, apk.Options{Blocklist: map[string]string{rep.SHA256: "dilaporkan"}}).Analyze(bytes.NewReader(b), int64(len(b)), "x.apk")
	if _, ok := ids(sigs)["apk.blocklisted"]; !ok {
		t.Error("blocklist")
	}
}

func TestInvalidInputs(t *testing.T) {
	a := analyzer(t, apk.Options{MaxSize: 1 << 20})
	for name, data := range map[string][]byte{
		"not zip":     []byte("hello world"),
		"no manifest": zipWith(t, "classes.dex", []byte("dex")),
		"bad axml":    zipWith(t, "AndroidManifest.xml", []byte{3, 0, 8, 0, 0xff, 0xff, 0, 0}),
		"text axml":   zipWith(t, "AndroidManifest.xml", []byte("<manifest/>")),
	} {
		_, sigs, err := a.Analyze(bytes.NewReader(data), int64(len(data)), name)
		if err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		if _, ok := ids(sigs)["apk.invalid"]; !ok {
			t.Errorf("%s: expected apk.invalid, got %v", name, sigs)
		}
	}
	big := make([]byte, 2<<20)
	if _, _, err := a.Analyze(bytes.NewReader(big), int64(len(big)), "big.apk"); err == nil {
		t.Error("expected size error")
	}
}

func FuzzAnalyze(f *testing.F) {
	f.Add(apktest.Build(scamSpec))
	f.Add([]byte("PK\x03\x04"))
	d, _ := refdata.Load(rules.FS)
	a := apk.New(d, apk.Options{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = a.Analyze(bytes.NewReader(b), int64(len(b)), "f.apk")
	})
}
