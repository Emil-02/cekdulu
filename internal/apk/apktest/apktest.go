// Package apktest builds small synthetic APK files for tests and demos.
// The generated files contain a real binary AndroidManifest.xml, optional
// resources.arsc, fake dex strings and signing certificates, but no code:
// they are harmless and cannot be installed.
package apktest

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"time"
	"unicode/utf16"
)

// Component is a <service> or <receiver>.
type Component struct {
	Name       string
	Permission string
	Actions    []string
}

// Spec describes the APK to generate.
type Spec struct {
	Package     string
	VersionName string
	Label       string
	// LabelInResources stores the label in resources.arsc and references it
	// from the manifest (like real apps do).
	LabelInResources bool
	MinSDK           int
	TargetSDK        int
	Permissions      []string
	Services         []Component
	Receivers        []Component
	// DexStrings are written into classes.dex verbatim.
	DexStrings []string
	// CertCN is the signing certificate common name. Empty = unsigned.
	CertCN string
	// CertNotBefore defaults to one year ago.
	CertNotBefore time.Time
	// V2 adds an APK Signature Scheme v2 block in addition to v1.
	V2 bool
}

const androidNS = "http://schemas.android.com/apk/res/android"

var attrIDs = map[string]uint32{
	"label":            0x01010001,
	"name":             0x01010003,
	"permission":       0x01010006,
	"minSdkVersion":    0x0101020c,
	"targetSdkVersion": 0x01010270,
	"versionName":      0x0101021c,
}

type attr struct {
	name    string
	android bool
	str     string
	isInt   bool
	isRef   bool
	val     uint32
}

type elem struct {
	name     string
	attrs    []attr
	children []elem
}

func sAttr(name, v string) attr        { return attr{name: name, android: true, str: v} }
func iAttr(name string, v int) attr    { return attr{name: name, android: true, isInt: true, val: uint32(v)} }
func rAttr(name string, v uint32) attr { return attr{name: name, android: true, isRef: true, val: v} }

// Build returns the bytes of a synthetic APK.
func Build(s Spec) []byte {
	man := elem{name: "manifest", attrs: []attr{{name: "package", str: s.Package}}}
	if s.VersionName != "" {
		man.attrs = append(man.attrs, sAttr("versionName", s.VersionName))
	}
	sdk := elem{name: "uses-sdk"}
	if s.MinSDK > 0 {
		sdk.attrs = append(sdk.attrs, iAttr("minSdkVersion", s.MinSDK))
	}
	if s.TargetSDK > 0 {
		sdk.attrs = append(sdk.attrs, iAttr("targetSdkVersion", s.TargetSDK))
	}
	man.children = append(man.children, sdk)
	for _, p := range s.Permissions {
		man.children = append(man.children, elem{name: "uses-permission", attrs: []attr{sAttr("name", p)}})
	}
	app := elem{name: "application"}
	if s.Label != "" {
		if s.LabelInResources {
			app.attrs = append(app.attrs, rAttr("label", 0x7f010000))
		} else {
			app.attrs = append(app.attrs, sAttr("label", s.Label))
		}
	}
	addComps := func(tag string, cs []Component) {
		for _, c := range cs {
			e := elem{name: tag, attrs: []attr{sAttr("name", c.Name)}}
			if c.Permission != "" {
				e.attrs = append(e.attrs, sAttr("permission", c.Permission))
			}
			if len(c.Actions) > 0 {
				f := elem{name: "intent-filter"}
				for _, a := range c.Actions {
					f.children = append(f.children, elem{name: "action", attrs: []attr{sAttr("name", a)}})
				}
				e.children = append(e.children, f)
			}
			app.children = append(app.children, e)
		}
	}
	addComps("service", s.Services)
	addComps("receiver", s.Receivers)
	man.children = append(man.children, app)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(name string, b []byte) {
		w, err := zw.Create(name)
		if err != nil {
			panic(err)
		}
		_, _ = w.Write(b)
	}
	write("AndroidManifest.xml", encodeAXML(man))
	if s.LabelInResources && s.Label != "" {
		write("resources.arsc", encodeARSC(s.Label))
	}
	dex := []byte("dex\n035\x00")
	for _, str := range s.DexStrings {
		dex = append(dex, 0)
		dex = append(dex, str...)
	}
	write("classes.dex", dex)

	var certDER []byte
	if s.CertCN != "" {
		certDER = selfSigned(s.CertCN, s.CertNotBefore)
		write("META-INF/MANIFEST.MF", []byte("Manifest-Version: 1.0\r\n"))
		write("META-INF/CERT.SF", []byte("Signature-Version: 1.0\r\n"))
		write("META-INF/CERT.RSA", pkcs7(certDER))
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	out := buf.Bytes()
	if s.V2 && certDER != nil {
		out = insertV2Block(out, certDER)
	}
	return out
}

// ---- binary XML encoder ----

type pool struct {
	strs []string
	idx  map[string]uint32
}

func (p *pool) add(s string) uint32 {
	if p.idx == nil {
		p.idx = map[string]uint32{}
	}
	if i, ok := p.idx[s]; ok {
		return i
	}
	p.idx[s] = uint32(len(p.strs))
	p.strs = append(p.strs, s)
	return p.idx[s]
}

func le16(b []byte, v uint16) []byte { return binary.LittleEndian.AppendUint16(b, v) }
func le32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }

func encodePool(strs []string) []byte {
	var data []byte
	var offs []uint32
	for _, s := range strs {
		offs = append(offs, uint32(len(data)))
		data = appendLen8(data, len(utf16.Encode([]rune(s))))
		data = appendLen8(data, len(s))
		data = append(data, s...)
		data = append(data, 0)
	}
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	hdr := 28
	start := hdr + 4*len(strs)
	var b []byte
	b = le16(b, 0x0001)
	b = le16(b, uint16(hdr))
	b = le32(b, uint32(start+len(data)))
	b = le32(b, uint32(len(strs)))
	b = le32(b, 0)
	b = le32(b, 0x100) // UTF-8
	b = le32(b, uint32(start))
	b = le32(b, 0)
	for _, o := range offs {
		b = le32(b, o)
	}
	return append(b, data...)
}

func appendLen8(b []byte, n int) []byte {
	if n > 0x7f {
		return append(b, byte(n>>8)|0x80, byte(n))
	}
	return append(b, byte(n))
}

func encodeAXML(root elem) []byte {
	var p pool
	// Attribute names with resource IDs come first, matching the resource map.
	var resMap []uint32
	for _, n := range []string{"label", "name", "permission", "minSdkVersion", "targetSdkVersion", "versionName"} {
		p.add(n)
		resMap = append(resMap, attrIDs[n])
	}
	nsIdx := p.add(androidNS)
	prefixIdx := p.add("android")

	var body []byte
	var walk func(e elem)
	walk = func(e elem) {
		nameIdx := p.add(e.name)
		var attrs []byte
		for _, a := range e.attrs {
			ns := uint32(0xFFFFFFFF)
			if a.android {
				ns = nsIdx
			}
			an := p.add(a.name)
			raw := uint32(0xFFFFFFFF)
			typ, data := byte(0x03), uint32(0)
			switch {
			case a.isInt:
				typ, data = 0x10, a.val
			case a.isRef:
				typ, data = 0x01, a.val
			default:
				raw = p.add(a.str)
				data = raw
			}
			attrs = le32(attrs, ns)
			attrs = le32(attrs, an)
			attrs = le32(attrs, raw)
			attrs = le16(attrs, 8)
			attrs = append(attrs, 0, typ)
			attrs = le32(attrs, data)
		}
		var c []byte
		c = le16(c, 0x0102)
		c = le16(c, 16)
		c = le32(c, uint32(16+20+len(attrs)))
		c = le32(c, 1)
		c = le32(c, 0xFFFFFFFF)
		c = le32(c, 0xFFFFFFFF)
		c = le32(c, nameIdx)
		c = le16(c, 20)
		c = le16(c, 20)
		c = le16(c, uint16(len(e.attrs)))
		c = le16(c, 0)
		c = le16(c, 0)
		c = le16(c, 0)
		body = append(body, c...)
		body = append(body, attrs...)
		for _, ch := range e.children {
			walk(ch)
		}
		var end []byte
		end = le16(end, 0x0103)
		end = le16(end, 16)
		end = le32(end, 24)
		end = le32(end, 1)
		end = le32(end, 0xFFFFFFFF)
		end = le32(end, 0xFFFFFFFF)
		end = le32(end, nameIdx)
		body = append(body, end...)
	}
	walk(root)

	ns := func(t uint16) []byte {
		var c []byte
		c = le16(c, t)
		c = le16(c, 16)
		c = le32(c, 24)
		c = le32(c, 1)
		c = le32(c, 0xFFFFFFFF)
		c = le32(c, prefixIdx)
		return le32(c, nsIdx)
	}
	var rm []byte
	rm = le16(rm, 0x0180)
	rm = le16(rm, 8)
	rm = le32(rm, uint32(8+4*len(resMap)))
	for _, id := range resMap {
		rm = le32(rm, id)
	}

	payload := encodePool(p.strs)
	payload = append(payload, rm...)
	payload = append(payload, ns(0x0100)...)
	payload = append(payload, body...)
	payload = append(payload, ns(0x0101)...)

	var out []byte
	out = le16(out, 0x0003)
	out = le16(out, 8)
	out = le32(out, uint32(8+len(payload)))
	return append(out, payload...)
}

// encodeARSC builds a resource table with a single string resource 0x7f010000.
func encodeARSC(value string) []byte {
	global := encodePool([]string{value})

	const cfgSize = 64
	typeHdr := 20 + cfgSize
	var typ []byte
	typ = le16(typ, 0x0201)
	typ = le16(typ, uint16(typeHdr))
	typ = le32(typ, uint32(typeHdr+4+16))
	typ = append(typ, 1, 0)
	typ = le16(typ, 0)
	typ = le32(typ, 1)
	typ = le32(typ, uint32(typeHdr+4))
	typ = le32(typ, cfgSize)
	typ = append(typ, make([]byte, cfgSize-4)...)
	typ = le32(typ, 0) // entry offset
	typ = le16(typ, 8) // entry size
	typ = le16(typ, 0)
	typ = le32(typ, 0)
	typ = le16(typ, 8) // Res_value
	typ = append(typ, 0, 0x03)
	typ = le32(typ, 0)

	var spec []byte
	spec = le16(spec, 0x0202)
	spec = le16(spec, 16)
	spec = le32(spec, 20)
	spec = append(spec, 1, 0)
	spec = le16(spec, 0)
	spec = le32(spec, 1)
	spec = le32(spec, 0)

	typeStrings := encodePool([]string{"string"})
	keyStrings := encodePool([]string{"app_name"})

	const pkgHdr = 288
	var sub []byte
	sub = append(sub, typeStrings...)
	sub = append(sub, keyStrings...)
	sub = append(sub, spec...)
	sub = append(sub, typ...)
	var pkg []byte
	pkg = le16(pkg, 0x0200)
	pkg = le16(pkg, pkgHdr)
	pkg = le32(pkg, uint32(pkgHdr+len(sub)))
	pkg = le32(pkg, 0x7f)
	pkg = append(pkg, make([]byte, 256)...)
	pkg = le32(pkg, pkgHdr)
	pkg = le32(pkg, 1)
	pkg = le32(pkg, uint32(pkgHdr+len(typeStrings)))
	pkg = le32(pkg, 1)
	pkg = le32(pkg, 0)
	pkg = append(pkg, sub...)

	var out []byte
	out = le16(out, 0x0002)
	out = le16(out, 12)
	out = le32(out, uint32(12+len(global)+len(pkg)))
	out = le32(out, 1)
	out = append(out, global...)
	return append(out, pkg...)
}

// ---- signing ----

func selfSigned(cn string, notBefore time.Time) []byte {
	if notBefore.IsZero() {
		notBefore = time.Now().AddDate(-1, 0, 0)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"cekdulu test"}},
		NotBefore:    notBefore,
		NotAfter:     notBefore.AddDate(25, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return der
}

func pkcs7(certDER []byte) []byte {
	type contentInfo struct{ ContentType asn1.ObjectIdentifier }
	type signedData struct {
		Version      int
		DigestAlgs   asn1.RawValue
		ContentInfo  contentInfo
		Certificates asn1.RawValue
		SignerInfos  asn1.RawValue
	}
	emptySet := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: []byte{}}
	sd := signedData{
		Version:      1,
		DigestAlgs:   emptySet,
		ContentInfo:  contentInfo{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}},
		Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certDER},
		SignerInfos:  emptySet,
	}
	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		panic(err)
	}
	ci := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdBytes},
	}
	b, err := asn1.Marshal(ci)
	if err != nil {
		panic(err)
	}
	return b
}

func lp(parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	return append(le32(nil, uint32(len(body))), body...)
}

func insertV2Block(zipBytes, certDER []byte) []byte {
	eocd := bytes.LastIndex(zipBytes, []byte{0x50, 0x4b, 0x05, 0x06})
	cdOff := binary.LittleEndian.Uint32(zipBytes[eocd+16:])

	signedData := lp(lp(), lp(lp(certDER)), lp())
	signer := lp(signedData, lp(), lp())
	value := lp(signer)
	pair := binary.LittleEndian.AppendUint64(nil, uint64(4+len(value)))
	pair = le32(pair, 0x7109871a)
	pair = append(pair, value...)

	size := uint64(len(pair) + 8 + 16)
	block := binary.LittleEndian.AppendUint64(nil, size)
	block = append(block, pair...)
	block = binary.LittleEndian.AppendUint64(block, size)
	block = append(block, "APK Sig Block 42"...)

	out := append([]byte{}, zipBytes[:cdOff]...)
	out = append(out, block...)
	out = append(out, zipBytes[cdOff:]...)
	newEOCD := eocd + len(block)
	binary.LittleEndian.PutUint32(out[newEOCD+16:], cdOff+uint32(len(block)))
	return out
}
