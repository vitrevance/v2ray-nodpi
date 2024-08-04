package nodpi

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

func containsSubslice[T comparable](s1 []T, s2 []T) int {
	l1 := len(s1)
	l2 := len(s2)
	if l2 > l1 {
		return -1
	}
	for i := 0; i < l1-l2; i++ {
		if slices.Equal(s1[i:l2+i], s2) {
			return i
		}
	}
	return -1
}

func extractSNI(t *layers.TLS) ([]byte, error) {
	for _, data := range t.AppData {
		if data.ContentType == 0 {
			return data.Payload, nil
		}
	}
	return nil, newError("SNI segment not found")
}

func removeSNI(t *layers.TLS) ([]byte, error) {
	sniIndex := -1
	for i, data := range t.Handshake {
		if data.ContentType == 0 {
			sniIndex = i
			break
		}
	}
	if sniIndex >= 0 {
		t.AppData[sniIndex], t.AppData[len(t.AppData)] = t.AppData[len(t.AppData)], t.AppData[sniIndex]
		t.AppData = t.AppData[:len(t.AppData)-1]
	}
	sb := gopacket.NewSerializeBuffer()
	err := t.SerializeTo(sb, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	})
	if err != nil {
		return nil, newError("failed to serialize TLS packet").Base(err)
	}
	return sb.Bytes(), nil
}

// func makeHandshakeWithSNIPart(base *layers.TLS, sni []byte) []byte {
// 	t := &layers.TLS{}
// 	t.Handshake = base.Handshake
// 	t.AppData = []layers.TLSAppDataRecord{
// 		layers.TLSAppDataRecord{
// 			TLSRecordHeader: ,
// 		}
// 	}
// }
