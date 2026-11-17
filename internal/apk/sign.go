package apk

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"io"
	"path"
	"strings"
	"time"
)

// CertInfo summarises a signing certificate.
type CertInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SHA256    string    `json:"sha256"`
	Debug     bool      `json:"debug"`
}

func certInfo(c *x509.Certificate) CertInfo {
	sum := sha256.Sum256(c.Raw)
	subj := c.Subject.String()
	return CertInfo{
		Subject:   subj,
		Issuer:    c.Issuer.String(),
		NotBefore: c.NotBefore.UTC(),
		NotAfter:  c.NotAfter.UTC(),
		SHA256:    hex.EncodeToString(sum[:]),
		Debug:     strings.Contains(subj, "Android Debug"),
	}
}

const (
	sigBlockMagic = "APK Sig Block 42"
	sigV2ID       = 0x7109871a
	sigV3ID       = 0xf05368c0
	sigV31ID      = 0x1b93ad61
	maxSigBlock   = 16 << 20
)

// signingBlockCerts extracts certificates from the APK Signing Block
// (schemes v2/v3). It returns the scheme names found.
func signingBlockCerts(r io.ReaderAt, size int64) ([]*x509.Certificate, []string) {
	cdOffset, ok := centralDirOffset(r, size)
	if !ok || cdOffset < 32 {
		return nil, nil
	}
	footer := make([]byte, 24)
	if _, err := r.ReadAt(footer, cdOffset-24); err != nil || string(footer[8:]) != sigBlockMagic {
		return nil, nil
	}
	blockSize := int64(binary.LittleEndian.Uint64(footer))
	start := cdOffset - blockSize - 8
	if blockSize < 24 || blockSize > maxSigBlock || start < 0 {
		return nil, nil
	}
	block := make([]byte, blockSize-24)
	if _, err := r.ReadAt(block, start+8); err != nil {
		return nil, nil
	}

	var certs []*x509.Certificate
	var schemes []string
	for off := 0; off+12 <= len(block); {
		n := binary.LittleEndian.Uint64(block[off:])
		if n < 4 || n > uint64(len(block)-off-8) {
			break
		}
		id := binary.LittleEndian.Uint32(block[off+8:])
		val := block[off+12 : off+8+int(n)]
		switch id {
		case sigV2ID, sigV3ID, sigV31ID:
			scheme := map[uint32]string{sigV2ID: "v2", sigV3ID: "v3", sigV31ID: "v3.1"}[id]
			schemes = append(schemes, scheme)
			certs = append(certs, schemeCerts(val)...)
		}
		off += 8 + int(n)
	}
	return certs, schemes
}

// lpSeq splits a uint32 length-prefixed sequence of uint32 length-prefixed items.
func lpItems(b []byte) [][]byte {
	var out [][]byte
	for off := 0; off+4 <= len(b); {
		n := int(binary.LittleEndian.Uint32(b[off:]))
		if n < 0 || off+4+n > len(b) {
			break
		}
		out = append(out, b[off+4:off+4+n])
		off += 4 + n
	}
	return out
}

func lpFirst(b []byte) []byte {
	items := lpItems(b)
	if len(items) == 0 {
		return nil
	}
	return items[0]
}

func schemeCerts(val []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, signer := range lpItems(lpFirst(val)) {
		signedData := lpFirst(signer)
		parts := lpItems(signedData)
		if len(parts) < 2 { // digests, certificates, ...
			continue
		}
		for _, der := range lpItems(parts[1]) {
			if c, err := x509.ParseCertificate(der); err == nil {
				certs = append(certs, c)
			}
		}
	}
	return certs
}

func centralDirOffset(r io.ReaderAt, size int64) (int64, bool) {
	const eocdMin = 22
	if size < eocdMin {
		return 0, false
	}
	n := min(size, eocdMin+65535)
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, size-n); err != nil {
		return 0, false
	}
	for i := len(buf) - eocdMin; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:]) == 0x06054b50 {
			return int64(binary.LittleEndian.Uint32(buf[i+16:])), true
		}
	}
	return 0, false
}

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type pkcs7SignedData struct {
	Version      int
	DigestAlgs   asn1.RawValue
	ContentInfo  asn1.RawValue
	Certificates asn1.RawValue `asn1:"optional,tag:0"`
	CRLs         asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos  asn1.RawValue
}

// v1Certs extracts certificates from JAR signature files (META-INF/*.RSA|DSA|EC).
func v1Certs(zr *zip.Reader) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, f := range zr.File {
		dir, name := path.Split(f.Name)
		ext := strings.ToUpper(path.Ext(name))
		if !strings.EqualFold(dir, "META-INF/") || (ext != ".RSA" && ext != ".DSA" && ext != ".EC") {
			continue
		}
		b, err := readEntry(f, 1<<20)
		if err != nil {
			continue
		}
		certs = append(certs, parsePKCS7Certs(b)...)
	}
	return certs
}

func parsePKCS7Certs(b []byte) []*x509.Certificate {
	var ci pkcs7ContentInfo
	if _, err := asn1.Unmarshal(b, &ci); err != nil {
		return nil
	}
	var sd pkcs7SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil
	}
	return certs
}

func dedupeCerts(certs []*x509.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	for _, c := range certs {
		dup := false
		for _, o := range out {
			if bytes.Equal(o.Raw, c.Raw) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, c)
		}
	}
	return out
}
