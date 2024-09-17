package nodpi

import (
	"encoding/binary"
	"fmt"
)

type TLSHeader struct {
	Type    uint8
	Version uint16
}

type TLSRecord struct {
	Header TLSHeader
	Body   []byte
}

var ReadMore = newError("TLS size is greater than provided buffer")

func (r *TLSRecord) Encode() []byte {
	b := make([]byte, len(r.Body)+5)
	b[0] = r.Header.Type
	binary.BigEndian.PutUint16(b[1:], r.Header.Version)
	binary.BigEndian.PutUint16(b[3:], uint16(len(r.Body)))
	copy(b[5:], r.Body)
	return b
}

// Modifies current to store `size` bytes and returns rest
func (r *TLSRecord) Split(size int) (TLSRecord, error) {
	if size >= len(r.Body) {
		return TLSRecord{}, newError("split: TLS too short")
	}
	t := TLSRecord{
		Header: r.Header,
	}
	t.Body = r.Body[size:]
	r.Body = r.Body[:size]
	return t, nil
}

func parseTLSHandshake(buf []byte) (TLSRecord, error) {
	if buf[0] != 22 {
		return TLSRecord{}, newError("not a TLS handshake")
	}
	version := binary.BigEndian.Uint16(buf[1:3])
	size := binary.BigEndian.Uint16(buf[3:5])
	if version != 0x0301 && version != 0x0302 && version != 0x0303 {
		return TLSRecord{}, newError(fmt.Sprintf("unknown TLS version %x", version))
	}
	if int(size+5) > len(buf) {
		return TLSRecord{}, ReadMore
	}
	return TLSRecord{
		Header: TLSHeader{
			Type:    22,
			Version: version,
		},
		Body: buf[5 : size+5],
	}, nil
}

func (r *TLSRecord) SNI() string {
	pos := 0
	end := len(r.Body)
	for pos+4 < end {
		extType := binary.BigEndian.Uint16(r.Body[pos : pos+2])
		extSize := int(binary.BigEndian.Uint16(r.Body[pos+2 : pos+4]))
		pos += 4
		if extType == 0 {
			if pos > end-2 {
				return ""
			}
			namesLength := int(binary.BigEndian.Uint16(r.Body[pos : pos+2]))
			pos += 2

			// iterate over name list
			n := pos
			pos += namesLength
			if pos > end {
				return ""
			}
			for n < pos-3 {
				nameType := r.Body[n]
				nameSize := int(binary.BigEndian.Uint16(r.Body[n+1 : n+3]))
				n += 3

				if nameType == 0 {
					if n+nameSize > end {
						return ""
					}
					return string(r.Body[n : n+nameSize])
				}
			}
		} else {
			pos += extSize
		}
	}
	return ""
}
