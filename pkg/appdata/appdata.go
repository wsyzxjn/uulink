// Package appdata implements the AppData message protocol that wraps
// channel payloads on the UU Remote data channels.
//
// Wire structure (reverse-engineered from official client capture):
//
//	Message = protobuf {
//	  field 1 = varint (1 = request direction)
//	  field 2 = varint (timestamp ms)
//	  field 3 = Header {
//	    field 1 = varint (message kind)
//	    field 2 = string (JSON metadata, e.g. {"seq":27})
//	    field 4 = bytes (channel capability routing blob)
//	  }
//	  field 4 = bytes (payload)  // the actual channel message
//	}
package appdata

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"
)

// capabilityBlob is the 16-byte routing blob observed in the captured
// session-setup message (identical to ConnectOptions field 11).
var capabilityBlob = []byte{0x08, 0x06, 0x10, 0x02, 0x18, 0x01, 0x20, 0x02, 0x30, 0x02, 0x38, 0x02, 0x40, 0x02, 0x48, 0x01}

var seqCounter atomic.Uint64

// Message is the AppData envelope.
type Message struct {
	Kind     int    // header field 1
	Metadata string // header field 2 (JSON)
	CapBytes []byte // header field 4
	Payload  []byte // field 4
}

// Encode serializes the message in the captured wire format.
func (m *Message) Encode() []byte {
	var buf []byte

	// field 1 = 1 (request)
	buf = appendVarintField(buf, 1, 1)

	// field 2 = timestamp ms
	buf = appendVarintField(buf, 2, uint64(time.Now().UnixMilli()))

	// field 3 = header
	var hdr []byte
	hdr = appendVarintField(hdr, 1, uint64(m.Kind))
	if m.Metadata != "" {
		hdr = appendBytesField(hdr, 2, []byte(m.Metadata))
	}
	if len(m.CapBytes) > 0 {
		hdr = appendBytesField(hdr, 4, m.CapBytes)
	}
	buf = appendBytesField(buf, 3, hdr)

	// field 4 = payload
	if len(m.Payload) > 0 {
		buf = appendBytesField(buf, 4, m.Payload)
	}

	return buf
}

// Decode parses an AppData message.
func Decode(data []byte) (*Message, error) {
	m := &Message{}
	pos := 0
	for pos < len(data) {
		tag, n := decodeVarint(data[pos:])
		if n == 0 {
			return nil, fmt.Errorf("bad varint at %d", pos)
		}
		pos += n
		fieldNum := tag >> 3
		wireType := tag & 7

		switch fieldNum {
		case 1:
			v, n := decodeVarint(data[pos:])
			if n == 0 {
				return nil, fmt.Errorf("bad field 1")
			}
			m.Kind = int(v)
			pos += n
		case 2:
			b, n, err := decodeBytesField(data[pos:], wireType)
			if err != nil {
				return nil, err
			}
			m.Payload = b
			pos += n
		case 3:
			b, n, err := decodeBytesField(data[pos:], wireType)
			if err != nil {
				return nil, err
			}
			if err := m.decodeHeader(b); err != nil {
				return nil, err
			}
			pos += n
		default:
			n, err := skipField(data[pos:], wireType)
			if err != nil {
				return nil, err
			}
			pos += n
		}
	}
	return m, nil
}

func (m *Message) decodeHeader(data []byte) error {
	pos := 0
	for pos < len(data) {
		tag, n := decodeVarint(data[pos:])
		if n == 0 {
			return fmt.Errorf("bad header varint at %d", pos)
		}
		pos += n
		fieldNum := tag >> 3
		wireType := tag & 7

		switch fieldNum {
		case 1:
			v, n := decodeVarint(data[pos:])
			if n == 0 {
				return fmt.Errorf("bad header field 1")
			}
			m.Kind = int(v)
			pos += n
		case 2:
			b, n, err := decodeBytesField(data[pos:], wireType)
			if err != nil {
				return err
			}
			m.Metadata = string(b)
			pos += n
		case 4:
			b, n, err := decodeBytesField(data[pos:], wireType)
			if err != nil {
				return err
			}
			m.CapBytes = b
			pos += n
		default:
			n, err := skipField(data[pos:], wireType)
			if err != nil {
				return err
			}
			pos += n
		}
	}
	return nil
}

// NextSeq returns an incrementing sequence number.
func NextSeq() uint64 {
	return seqCounter.Add(1)
}

// SessionSetup builds the session-setup message (like the captured
// {"seq":27} message with capability blob).
func SessionSetup() []byte {
	m := &Message{
		Kind:     1,
		Metadata: `{"seq":` + strconv.FormatUint(NextSeq(), 10) + `}`,
		CapBytes: capabilityBlob,
	}
	return m.Encode()
}

// Wrap wraps a channel payload in an AppData message.
func Wrap(kind int, payload []byte) []byte {
	m := &Message{
		Kind:     kind,
		Metadata: `{"seq":` + strconv.FormatUint(NextSeq(), 10) + `}`,
		CapBytes: capabilityBlob,
		Payload:  payload,
	}
	return m.Encode()
}

// protobuf helpers

func appendVarintField(buf []byte, fieldNum, value uint64) []byte {
	buf = appendVarint(buf, (fieldNum<<3)|0)
	buf = appendVarint(buf, value)
	return buf
}

func appendBytesField(buf []byte, fieldNum uint64, value []byte) []byte {
	buf = appendVarint(buf, (fieldNum<<3)|2)
	buf = appendVarint(buf, uint64(len(value)))
	return append(buf, value...)
}

func appendVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

func decodeVarint(data []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(data) && i < 10; i++ {
		b := data[i]
		v |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

func decodeBytesField(data []byte, wireType uint64) ([]byte, int, error) {
	if wireType != 2 {
		return nil, 0, fmt.Errorf("expected LEN wire type, got %d", wireType)
	}
	length, n := decodeVarint(data)
	if n == 0 {
		return nil, 0, fmt.Errorf("bad length varint")
	}
	if int(length) > len(data)-n {
		return nil, 0, fmt.Errorf("length %d exceeds data", length)
	}
	return data[n : n+int(length)], n + int(length), nil
}

func skipField(data []byte, wireType uint64) (int, error) {
	switch wireType {
	case 0:
		_, n := decodeVarint(data)
		if n == 0 {
			return 0, fmt.Errorf("bad varint")
		}
		return n, nil
	case 1:
		return 8, nil
	case 2:
		_, n, err := decodeBytesField(data, 2)
		return n, err
	case 5:
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported wire type %d", wireType)
	}
}

// EncodeInt encodes a fixed helper for external use.
func EncodeInt(v uint64) []byte {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], v)
	return buf[:n]
}
