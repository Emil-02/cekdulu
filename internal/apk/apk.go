// Package apk performs static analysis of Android packages. APK files are
// never executed or installed: the analyzer only reads the manifest,
// resources, signing certificates and raw strings inside the archive.
package apk

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Emil-02/cekdulu/internal/refdata"
	"github.com/Emil-02/cekdulu/internal/score"
)

// DefaultMaxSize is the largest APK accepted by default.
const DefaultMaxSize = 150 << 20

// ErrTooLarge is returned when the APK exceeds Options.MaxSize.
var ErrTooLarge = errors.New("file terlalu besar")

// Options configure the analyzer.
type Options struct {
	MaxSize int64
	Now     func() time.Time
	// Blocklist maps lowercase SHA-256 hashes of known scam APKs to a reason.
	Blocklist map[string]string
}

// Report contains the facts extracted from an APK.
type Report struct {
	FileName       string     `json:"file_name,omitempty"`
	Size           int64      `json:"size"`
	SHA256         string     `json:"sha256"`
	Package        string     `json:"package,omitempty"`
	Label          string     `json:"label,omitempty"`
	VersionName    string     `json:"version_name,omitempty"`
	MinSDK         int        `json:"min_sdk,omitempty"`
	TargetSDK      int        `json:"target_sdk,omitempty"`
	Permissions    []string   `json:"permissions"`
	Components     []string   `json:"sensitive_components,omitempty"`
	SigningSchemes []string   `json:"signing_schemes,omitempty"`
	Certificates   []CertInfo `json:"certificates,omitempty"`
	TelegramBots   []string   `json:"telegram_bots,omitempty"`
	Hosts          []string   `json:"embedded_hosts,omitempty"`
	Notes          []string   `json:"notes,omitempty"`
}

// Analyzer inspects APK files. It is safe for concurrent use.
type Analyzer struct {
	data *refdata.Data
	opt  Options
}

// New returns an analyzer.
func New(data *refdata.Data, opt Options) *Analyzer {
	if opt.MaxSize == 0 {
		opt.MaxSize = DefaultMaxSize
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Analyzer{data: data, opt: opt}
}

// AnalyzeFile analyses the APK at path.
func (a *Analyzer) AnalyzeFile(p string) (Report, []score.Signal, error) {
	f, err := os.Open(p)
	if err != nil {
		return Report{}, nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Report{}, nil, err
	}
	return a.Analyze(f, st.Size(), path.Base(strings.ReplaceAll(p, "\\", "/")))
}

// Analyze inspects an APK provided as a ReaderAt. The returned error is only
// non-nil for I/O or size problems; a non-APK file yields an apk.invalid
// signal instead.
func (a *Analyzer) Analyze(r io.ReaderAt, size int64, fileName string) (Report, []score.Signal, error) {
	rep := Report{FileName: fileName, Size: size, Permissions: []string{}}
	if size > a.opt.MaxSize {
		return rep, nil, fmt.Errorf("%w: maksimal %d MB", ErrTooLarge, a.opt.MaxSize>>20)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(r, 0, size)); err != nil {
		return rep, nil, err
	}
	rep.SHA256 = hex.EncodeToString(h.Sum(nil))

	var sigs []score.Signal
	add := func(id, detail string) { sigs = append(sigs, score.Signal{ID: id, Detail: detail}) }
	if reason, ok := a.opt.Blocklist[rep.SHA256]; ok {
		add("apk.blocklisted", reason)
	}

	zr, err := zip.NewReader(r, size)
	if err != nil {
		add("apk.invalid", "bukan arsip ZIP/APK")
		return rep, sigs, nil
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		if _, dup := files[f.Name]; !dup {
			files[f.Name] = f
		}
	}
	mf, ok := files["AndroidManifest.xml"]
	if !ok {
		add("apk.invalid", "AndroidManifest.xml tidak ditemukan")
		return rep, sigs, nil
	}
	raw, err := readEntry(mf, 8<<20)
	if err != nil {
		add("apk.invalid", "manifest tidak bisa dibaca")
		return rep, sigs, nil
	}
	events, err := parseAXML(raw)
	if err != nil {
		add("apk.invalid", "manifest rusak: "+err.Error())
		return rep, sigs, nil
	}

	m := readManifest(events)
	rep.Package, rep.VersionName, rep.MinSDK, rep.TargetSDK = m.pkg, m.versionName, m.minSDK, m.targetSDK
	rep.Label = m.label
	if m.labelRef != 0 {
		if arsc, ok := files["resources.arsc"]; ok {
			if b, err := readEntry(arsc, 64<<20); err == nil {
				rep.Label = resolveString(b, m.labelRef)
			}
		}
		if rep.Label == "" {
			rep.Notes = append(rep.Notes, "nama aplikasi tidak bisa dibaca dari resources")
		}
	}
	rep.Permissions = m.permissions
	rep.Components = m.components

	for _, p := range m.permissions {
		if short, ok := strings.CutPrefix(p, "android.permission."); ok {
			add("apk.perm."+short, "")
		}
	}
	for _, c := range m.signals {
		add(c, "")
	}
	target := rep.TargetSDK
	if target == 0 {
		target = rep.MinSDK
	}
	if target > 0 && target < 23 {
		add("apk.target_sdk_old", fmt.Sprint(target))
	}
	if isGenericPackage(rep.Package) {
		add("apk.package.generic", rep.Package)
	}

	names := rep.Label + " " + strings.TrimSuffix(fileName, path.Ext(fileName))
	if lures := matchTokens(names, a.data.APKLures); len(lures) > 0 {
		add("apk.lure_name", strings.Join(lures, ", "))
	}
	if brand, ok := a.impersonates(names, rep.Package); ok {
		add("apk.brand_impersonation", brand)
	}

	// Certificates.
	certs, schemes := signingBlockCerts(r, size)
	if v1 := v1Certs(zr); len(v1) > 0 {
		schemes = append([]string{"v1"}, schemes...)
		certs = append(certs, v1...)
	}
	rep.SigningSchemes = schemes
	for _, c := range dedupeCerts(certs) {
		rep.Certificates = append(rep.Certificates, certInfo(c))
	}
	if len(rep.Certificates) == 0 {
		add("apk.cert.missing", "")
	}
	for _, c := range rep.Certificates {
		if c.Debug {
			add("apk.cert.debug", "")
		}
		if age := a.opt.Now().Sub(c.NotBefore); age >= 0 && age < 60*24*time.Hour {
			add("apk.cert.recent", fmt.Sprintf("%d hari lalu", int(age.Hours()/24)))
		}
	}

	// Raw string scan: dex code, resources and small assets.
	bots, hosts := scanStrings(zr)
	rep.TelegramBots, rep.Hosts = bots, hosts
	if len(bots) > 0 {
		add("apk.telegram_bot", strings.Join(bots, ", "))
	}
	return rep, sigs, nil
}

type manifest struct {
	pkg, versionName, label string
	labelRef                uint32
	minSDK, targetSDK       int
	permissions, components []string
	signals                 []string
}

func readManifest(events []xmlEvent) manifest {
	var m manifest
	perms := map[string]bool{}
	sigSet := map[string]bool{}
	var stack []xmlEvent
	var comp *xmlEvent // current service/receiver

	flag := func(sig, desc string) {
		if !sigSet[sig] {
			sigSet[sig] = true
			m.signals = append(m.signals, sig)
		}
		if comp != nil {
			n, _ := comp.attr("name")
			m.components = append(m.components, fmt.Sprintf("%s %s (%s)", comp.Name, n.Value, desc))
		}
	}
	checkPermission := func(p string) {
		switch p {
		case "android.permission.BIND_ACCESSIBILITY_SERVICE":
			flag("apk.service.accessibility", "aksesibilitas")
		case "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
			flag("apk.service.notification_listener", "pembaca notifikasi")
		case "android.permission.BIND_DEVICE_ADMIN":
			flag("apk.receiver.device_admin", "admin perangkat")
		case "android.permission.BROADCAST_SMS":
			flag("apk.receiver.sms", "penerima SMS")
		}
	}

	for i := range events {
		ev := events[i]
		if !ev.Start {
			if len(stack) > 0 {
				if top := stack[len(stack)-1]; top.Name == "service" || top.Name == "receiver" {
					comp = nil
				}
				stack = stack[:len(stack)-1]
			}
			continue
		}
		stack = append(stack, ev)
		switch ev.Name {
		case "manifest":
			if a, ok := ev.attr("package"); ok {
				m.pkg = a.Value
			}
			if a, ok := ev.attr("versionName"); ok {
				m.versionName = a.Value
			}
		case "uses-sdk":
			if a, ok := ev.attr("minSdkVersion"); ok {
				m.minSDK = int(a.Int)
			}
			if a, ok := ev.attr("targetSdkVersion"); ok {
				m.targetSDK = int(a.Int)
			}
		case "uses-permission", "uses-permission-sdk-23":
			if a, ok := ev.attr("name"); ok && a.Value != "" && !perms[a.Value] {
				perms[a.Value] = true
				m.permissions = append(m.permissions, a.Value)
			}
		case "application":
			if a, ok := ev.attr("label"); ok {
				if a.Ref != 0 {
					m.labelRef = a.Ref
				} else {
					m.label = a.Value
				}
			}
		case "service", "receiver":
			comp = &events[i]
			if a, ok := ev.attr("permission"); ok {
				checkPermission(a.Value)
			}
		case "action":
			a, _ := ev.attr("name")
			switch a.Value {
			case "android.accessibilityservice.AccessibilityService":
				flag("apk.service.accessibility", "aksesibilitas")
			case "android.service.notification.NotificationListenerService":
				flag("apk.service.notification_listener", "pembaca notifikasi")
			case "android.provider.Telephony.SMS_RECEIVED", "android.provider.Telephony.SMS_DELIVER":
				flag("apk.receiver.sms", "penerima SMS")
			case "android.app.action.DEVICE_ADMIN_ENABLED":
				flag("apk.receiver.device_admin", "admin perangkat")
			}
		}
	}
	sort.Strings(m.permissions)
	m.components = uniqueSorted(m.components)
	return m
}

func (a *Analyzer) impersonates(names, pkg string) (string, bool) {
	tokens := tokenize(names)
	for _, b := range a.data.Brands {
		if len(b.Packages) == 0 {
			continue
		}
		hit := false
		for _, kw := range b.Keywords {
			for _, t := range tokens {
				if t == kw || (len(kw) >= 5 && strings.Contains(t, kw)) {
					hit = true
				}
			}
		}
		if !hit {
			continue
		}
		for _, p := range b.Packages {
			if pkg == p || strings.HasPrefix(pkg, p+".") {
				return "", false
			}
		}
		return b.Name, true
	}
	return "", false
}

var (
	reTelegramURL   = regexp.MustCompile(`api\.telegram\.org/bot(\d{6,12}:[A-Za-z0-9_-]{30,40})`)
	reTelegramToken = regexp.MustCompile(`\b(\d{8,11}:AA[A-Za-z0-9_-]{33})\b`)
	reHost          = regexp.MustCompile(`https?://([a-zA-Z0-9][a-zA-Z0-9.-]{1,252}\.[a-zA-Z]{2,24})`)
)

var ignoredHosts = []string{
	"schemas.android.com", "android.com", "google.com", "googleapis.com", "gstatic.com", "w3.org",
	"apache.org", "xmlpull.org", "ns.adobe.com", "jetbrains.org", "kotlinlang.org", "github.com",
	"firebaseio.com", "crashlytics.com", "googlesyndication.com", "doubleclick.net", "app-measurement.com",
	"facebook.com", "youtube.com", "telegram.org", "example.com", "openxmlformats.org", "purl.org", "mozilla.org",
}

const maxScanBytes = 128 << 20

func scanStrings(zr *zip.Reader) (bots, hosts []string) {
	botSet := map[string]bool{}
	hostSet := map[string]bool{}
	var budget int64 = maxScanBytes
	for _, f := range zr.File {
		name := f.Name
		isDex := strings.HasSuffix(name, ".dex")
		scan := isDex || name == "resources.arsc" ||
			(strings.HasPrefix(name, "assets/") && f.UncompressedSize64 < 5<<20)
		if !scan || budget <= 0 {
			continue
		}
		b, err := readEntry(f, min(budget, 64<<20))
		if err != nil {
			continue
		}
		budget -= int64(len(b))
		for _, m := range reTelegramURL.FindAllSubmatch(b, -1) {
			botSet[maskToken(string(m[1]))] = true
		}
		for _, m := range reTelegramToken.FindAllSubmatch(b, -1) {
			botSet[maskToken(string(m[1]))] = true
		}
		for _, m := range reHost.FindAllSubmatch(b, -1) {
			h := strings.ToLower(string(m[1]))
			if !ignoredHost(h) {
				hostSet[h] = true
			}
		}
	}
	bots = keys(botSet)
	hosts = keys(hostSet)
	if len(hosts) > 20 {
		hosts = hosts[:20]
	}
	return bots, hosts
}

// maskToken keeps the bot ID and hides the secret part.
func maskToken(tok string) string {
	id, secret, ok := strings.Cut(tok, ":")
	if !ok || len(secret) < 4 {
		return "bot ***"
	}
	return "bot " + id + ":" + secret[:2] + strings.Repeat("*", 6)
}

func ignoredHost(h string) bool {
	for _, d := range ignoredHosts {
		if refdata.MatchesDomain(h, d) {
			return true
		}
	}
	return false
}

func isGenericPackage(pkg string) bool {
	p := strings.ToLower(pkg)
	return strings.HasPrefix(p, "com.example.") || strings.Contains(p, "myapplication") ||
		strings.HasPrefix(p, "com.test.") || strings.HasPrefix(p, "com.demo.")
}

func readEntry(f *zip.File, limit int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(limit) {
		return nil, ErrTooLarge
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, ErrTooLarge
	}
	return b, nil
}

func tokenize(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func matchTokens(s string, words []string) []string {
	var out []string
	tokens := tokenize(s)
	for _, w := range words {
		for _, t := range tokens {
			if t == w || (len(w) >= 5 && strings.Contains(t, w)) {
				out = append(out, w)
				break
			}
		}
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func uniqueSorted(in []string) []string {
	m := map[string]bool{}
	for _, s := range in {
		m[s] = true
	}
	return keys(m)
}
