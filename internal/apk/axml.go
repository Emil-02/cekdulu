package apk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// Android binary XML (AXML) chunk types.
const (
	chunkStringPool   = 0x0001
	chunkTable        = 0x0002
	chunkXML          = 0x0003
	chunkXMLStartNS   = 0x0100
	chunkXMLEndNS     = 0x0101
	chunkXMLStartElem = 0x0102
	chunkXMLEndElem   = 0x0103
	chunkXMLResMap    = 0x0180
	chunkTablePackage = 0x0200
	chunkTableType    = 0x0201
	chunkTableSpec    = 0x0202

	typeReference = 0x01
	typeString    = 0x03
	typeIntDec    = 0x10
	typeIntHex    = 0x11
	typeIntBool   = 0x12

	noIndex = 0xFFFFFFFF
)

var errMalformed = errors.New("format biner rusak")

// Well-known android attribute resource IDs, used when attribute names are
// stripped by obfuscators.
var attrByResID = map[uint32]string{
	0x01010001: "label",
	0x01010003: "name",
	0x01010006: "permission",
	0x0101020c: "minSdkVersion",
	0x01010270: "targetSdkVersion",
	0x0101021b: "versionCode",
	0x0101021c: "versionName",
}

// xmlAttr is a decoded attribute.
type xmlAttr struct {
	Name  string
	Value string
	// Ref is set when the value is a resource reference (@0x7f...).
	Ref uint32
	Int int64
	Typ uint8
}

// xmlEvent is a start or end element.
type xmlEvent struct {
	Start bool
	Name  string
	Attrs []xmlAttr
}

func (e xmlEvent) attr(name string) (xmlAttr, bool) {
	for _, a := range e.Attrs {
		if a.Name == name {
			return a, true
		}
	}
	return xmlAttr{}, false
}

// stringPool is a decoded ResStringPool.
type stringPool []string

func (p stringPool) get(i uint32) string {
	if i == noIndex || int(i) >= len(p) {
		return ""
	}
	return p[i]
}

func u16(b []byte, off int) (uint16, error) {
	if off < 0 || off+2 > len(b) {
		return 0, errMalformed
	}
	return binary.LittleEndian.Uint16(b[off:]), nil
}

func u32(b []byte, off int) (uint32, error) {
	if off < 0 || off+4 > len(b) {
		return 0, errMalformed
	}
	return binary.LittleEndian.Uint32(b[off:]), nil
}

// chunkHeader reads type, headerSize and size at off and validates bounds.
func chunkHeader(b []byte, off int) (typ uint16, hdr int, size int, err error) {
	t, err := u16(b, off)
	if err != nil {
		return 0, 0, 0, err
	}
	h, err := u16(b, off+2)
	if err != nil {
		return 0, 0, 0, err
	}
	s, err := u32(b, off+4)
	if err != nil {
		return 0, 0, 0, err
	}
	if int(h) < 8 || int(s) < int(h) || off+int(s) > len(b) {
		return 0, 0, 0, errMalformed
	}
	return t, int(h), int(s), nil
}

const maxStrings = 1 << 20

func parseStringPool(chunk []byte) (stringPool, error) {
	count, err := u32(chunk, 8)
	if err != nil {
		return nil, err
	}
	flags, _ := u32(chunk, 16)
	start, err := u32(chunk, 20)
	if err != nil {
		return nil, err
	}
	if count > maxStrings || 28+int(count)*4 > len(chunk) {
		return nil, errMalformed
	}
	utf8 := flags&0x100 != 0
	pool := make(stringPool, count)
	for i := range int(count) {
		rel, _ := u32(chunk, 28+i*4)
		off := int(start) + int(rel)
		if off < 0 || off >= len(chunk) {
			continue
		}
		if utf8 {
			pool[i] = readUTF8(chunk, off)
		} else {
			pool[i] = readUTF16(chunk, off)
		}
	}
	return pool, nil
}

func readUTF8(b []byte, off int) string {
	// skip UTF-16 length (1 or 2 bytes)
	if off >= len(b) {
		return ""
	}
	if b[off]&0x80 != 0 {
		off += 2
	} else {
		off++
	}
	if off >= len(b) {
		return ""
	}
	n := int(b[off])
	if b[off]&0x80 != 0 {
		if off+1 >= len(b) {
			return ""
		}
		n = int(b[off]&0x7f)<<8 | int(b[off+1])
		off += 2
	} else {
		off++
	}
	if off+n > len(b) {
		return ""
	}
	return string(b[off : off+n])
}

func readUTF16(b []byte, off int) string {
	n16, err := u16(b, off)
	if err != nil {
		return ""
	}
	n := int(n16)
	off += 2
	if n16&0x8000 != 0 {
		lo, err := u16(b, off)
		if err != nil {
			return ""
		}
		n = int(n16&0x7fff)<<16 | int(lo)
		off += 2
	}
	if n > maxStrings || off+n*2 > len(b) {
		return ""
	}
	units := make([]uint16, n)
	for i := range n {
		units[i] = binary.LittleEndian.Uint16(b[off+i*2:])
	}
	return string(utf16.Decode(units))
}

// parseAXML decodes a binary XML document into a flat list of events.
func parseAXML(b []byte) ([]xmlEvent, error) {
	typ, hdr, size, err := chunkHeader(b, 0)
	if err != nil {
		return nil, err
	}
	if typ != chunkXML {
		return nil, fmt.Errorf("bukan binary XML")
	}
	var (
		pool   stringPool
		resMap []uint32
		events []xmlEvent
	)
	for off := hdr; off < size; {
		ct, ch, cs, err := chunkHeader(b, off)
		if err != nil {
			return nil, err
		}
		chunk := b[off : off+cs]
		switch ct {
		case chunkStringPool:
			if pool, err = parseStringPool(chunk); err != nil {
				return nil, err
			}
		case chunkXMLResMap:
			for i := ch; i+4 <= cs; i += 4 {
				resMap = append(resMap, binary.LittleEndian.Uint32(chunk[i:]))
			}
		case chunkXMLStartElem:
			ev, err := parseStartElem(chunk, ch, pool, resMap)
			if err != nil {
				return nil, err
			}
			events = append(events, ev)
		case chunkXMLEndElem:
			name, _ := u32(chunk, ch+4)
			events = append(events, xmlEvent{Name: pool.get(name)})
		}
		off += cs
	}
	return events, nil
}

func parseStartElem(c []byte, hdr int, pool stringPool, resMap []uint32) (xmlEvent, error) {
	nameIdx, err := u32(c, hdr+4)
	if err != nil {
		return xmlEvent{}, err
	}
	attrStart, _ := u16(c, hdr+8)
	attrSize, _ := u16(c, hdr+10)
	attrCount, err := u16(c, hdr+12)
	if err != nil {
		return xmlEvent{}, err
	}
	if attrSize < 20 {
		attrSize = 20
	}
	ev := xmlEvent{Start: true, Name: pool.get(nameIdx)}
	for i := range int(attrCount) {
		a := hdr + int(attrStart) + i*int(attrSize)
		if a+20 > len(c) {
			return ev, errMalformed
		}
		nameI := binary.LittleEndian.Uint32(c[a+4:])
		raw := binary.LittleEndian.Uint32(c[a+8:])
		dt := c[a+15]
		data := binary.LittleEndian.Uint32(c[a+16:])

		name := pool.get(nameI)
		if int(nameI) < len(resMap) {
			if n, ok := attrByResID[resMap[nameI]]; ok {
				name = n
			}
		}
		at := xmlAttr{Name: name, Typ: dt}
		switch {
		case raw != noIndex:
			at.Value = pool.get(raw)
		case dt == typeString:
			at.Value = pool.get(data)
		case dt == typeReference:
			at.Ref = data
			at.Value = fmt.Sprintf("@0x%08x", data)
		case dt == typeIntBool:
			at.Int = int64(data)
			at.Value = fmt.Sprint(data != 0)
		case dt >= typeIntDec && dt <= 0x1f:
			at.Int = int64(int32(data))
			at.Value = fmt.Sprint(at.Int)
		}
		ev.Attrs = append(ev.Attrs, at)
	}
	return ev, nil
}

// resolveString looks up a string resource in resources.arsc, preferring
// the default configuration. It returns "" when not found.
func resolveString(arsc []byte, id uint32) string {
	typ, hdr, size, err := chunkHeader(arsc, 0)
	if err != nil || typ != chunkTable {
		return ""
	}
	var global stringPool
	wantPkg := id >> 24
	wantType := (id >> 16) & 0xff
	wantEntry := id & 0xffff
	var fallback string

	for off := hdr; off < size; {
		ct, ch, cs, err := chunkHeader(arsc, off)
		if err != nil {
			return fallback
		}
		chunk := arsc[off : off+cs]
		switch ct {
		case chunkStringPool:
			global, _ = parseStringPool(chunk)
		case chunkTablePackage:
			pkgID, _ := u32(chunk, 8)
			if pkgID != wantPkg {
				break
			}
			for p := ch; p < cs; {
				pt, phdr, ps, err := chunkHeader(chunk, p)
				if err != nil {
					return fallback
				}
				if pt == chunkTableType {
					v, isDefault, ok := typeEntryString(chunk[p:p+ps], phdr, wantType, wantEntry, global)
					if ok {
						if isDefault {
							return v
						}
						if fallback == "" {
							fallback = v
						}
					}
				}
				p += ps
			}
		}
		off += cs
	}
	return fallback
}

func typeEntryString(c []byte, hdr int, wantType, wantEntry uint32, global stringPool) (string, bool, bool) {
	if len(c) < 20 || uint32(c[8]) != wantType {
		return "", false, false
	}
	flags := c[9]
	count, _ := u32(c, 12)
	entriesStart, _ := u32(c, 16)
	if wantEntry >= count {
		return "", false, false
	}
	// ResTable_config begins at offset 20; its first field is its size.
	cfgSize, _ := u32(c, 20)
	isDefault := true
	if cfgSize > 4 && 20+int(cfgSize) <= len(c) {
		for _, x := range c[24 : 20+int(cfgSize)] {
			if x != 0 {
				isDefault = false
				break
			}
		}
	}
	var entryOff uint32
	if flags&0x01 != 0 { // sparse: (idx u16, offset/4 u16) pairs
		found := false
		for i := range int(count) {
			idx, err := u16(c, hdr+i*4)
			if err != nil {
				return "", false, false
			}
			if uint32(idx) == wantEntry {
				o, _ := u16(c, hdr+i*4+2)
				entryOff, found = uint32(o)*4, true
				break
			}
		}
		if !found {
			return "", false, false
		}
	} else if flags&0x02 != 0 { // 16-bit offsets (offset/4), 0xffff = none
		o, err := u16(c, hdr+int(wantEntry)*2)
		if err != nil || o == 0xffff {
			return "", false, false
		}
		entryOff = uint32(o) * 4
	} else {
		o, err := u32(c, hdr+int(wantEntry)*4)
		if err != nil || o == noIndex {
			return "", false, false
		}
		entryOff = o
	}
	e := int(entriesStart) + int(entryOff)
	entrySize, err := u16(c, e)
	if err != nil {
		return "", false, false
	}
	entryFlags, _ := u16(c, e+2)
	if entryFlags&0x0008 != 0 { // compact entry: type in high byte of flags
		data, err := u32(c, e+4)
		if err != nil || entryFlags>>8 != typeString {
			return "", false, false
		}
		return global.get(data), isDefault, true
	}
	if entryFlags&0x0001 != 0 { // complex (bag) entry
		return "", false, false
	}
	v := e + int(entrySize)
	if v+8 > len(c) || c[v+3] != typeString {
		return "", false, false
	}
	data := binary.LittleEndian.Uint32(c[v+4:])
	return global.get(data), isDefault, true
}
