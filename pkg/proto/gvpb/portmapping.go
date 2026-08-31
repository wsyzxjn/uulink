// Package gvpb implements the UU Remote port mapping frame protocol.
//
// The official client transports port mapping messages as binary protobuf
// ("pbMessage") on the FILE data channel. The JSON structure seen in official
// client debug logs ("sentProtocolBufferfile Message: {...}") maps to this
// protobuf schema:
//
//	Message {
//	  uint64 seq = 1;
//	  uint64 timestamp = 2;   // sender uses seconds, receiver may use milliseconds
//	  PortMappingFrame portMappingFrame = 27;
//	}
//	PortMappingFrame {
//	  uint32 session_id = 1;  // always 1 in captured sessions
//	  uint64 rule_id    = 2;  // registered numeric MMKV rule ID
//	  uint32 stream_id  = 3;
//	  FrameType type    = 4;  // SYN=0, FIN=1, DATA=2, SYN_ACK=3, DATA_ACK=4
//	  bytes payload     = 5;
//	}
package gvpb

import (
	"fmt"
	"strconv"
	"sync/atomic"
)

// FrameType identifies the port mapping frame type.
type FrameType string

const (
	// TypeConnect is the wire enum named SYN in the official descriptor.
	TypeConnect FrameType = "SYN"
	TypeSynAck  FrameType = "SYN_ACK"
	TypeData    FrameType = "DATA"
	TypeDataAck FrameType = "DATA_ACK"
	TypeFin     FrameType = "FIN"
)

// PortMappingFrame is one port mapping frame.
type PortMappingFrame struct {
	SessionID string    `json:"sessionId,omitempty"`
	RuleID    string    `json:"ruleId,omitempty"`
	StreamID  string    `json:"streamId,omitempty"`
	Type      FrameType `json:"type,omitempty"`
	Payload   []byte    `json:"payload,omitempty"`
}

// Message wraps a PortMappingFrame with sequencing metadata.
type Message struct {
	Seq              string            `json:"seq"`
	Timestamp        string            `json:"timestamp"`
	PortMappingFrame *PortMappingFrame `json:"portMappingFrame,omitempty"`
}

var msgSeqCounter atomic.Uint64

// NextSeq returns the next message sequence as a decimal string.
func NextSeq() string {
	return fmt.Sprintf("%d", msgSeqCounter.Add(1))
}

// Encode serializes the Message as protobuf.
func (m *Message) Encode() ([]byte, error) {
	var buf []byte
	if m.Seq != "" {
		v, err := strconv.ParseUint(m.Seq, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad message seq: %w", err)
		}
		buf = appendFieldVarint(buf, 1, v)
	}
	if m.Timestamp != "" {
		v, err := strconv.ParseUint(m.Timestamp, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad message timestamp: %w", err)
		}
		buf = appendFieldVarint(buf, 2, v)
	}
	if m.PortMappingFrame != nil {
		frame, err := m.PortMappingFrame.encode()
		if err != nil {
			return nil, err
		}
		buf = appendFieldBytes(buf, 27, frame)
	}
	return buf, nil
}

// DecodeMessage parses a protobuf-encoded Message.
func DecodeMessage(data []byte) (*Message, error) {
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
		case 1, 2:
			if wireType != 0 {
				return nil, fmt.Errorf("message field %d: expected varint, got wire type %d", fieldNum, wireType)
			}
			v, n := decodeVarint(data[pos:])
			if n == 0 {
				return nil, fmt.Errorf("bad message field %d", fieldNum)
			}
			pos += n
			s := strconv.FormatUint(v, 10)
			if fieldNum == 1 {
				m.Seq = s
			} else {
				m.Timestamp = s
			}
		case 27:
			b, n, err := decodeBytesField(data[pos:], wireType)
			pos += n
			frame, err := decodeFrame(b)
			if err != nil {
				return nil, fmt.Errorf("decode frame: %w", err)
			}
			m.PortMappingFrame = frame
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

func (f *PortMappingFrame) encode() ([]byte, error) {
	var buf []byte
	if f.SessionID != "" {
		v, err := strconv.ParseUint(f.SessionID, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad session id: %w", err)
		}
		buf = appendFieldVarint(buf, 1, v)
	}
	if f.RuleID != "" {
		v, err := strconv.ParseUint(f.RuleID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad rule id: %w", err)
		}
		buf = appendFieldVarint(buf, 2, v)
	}
	if f.StreamID != "" {
		v, err := strconv.ParseUint(f.StreamID, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad stream id: %w", err)
		}
		buf = appendFieldVarint(buf, 3, v)
	}
	if f.Type != "" {
		v, err := frameTypeValue(f.Type)
		if err != nil {
			return nil, err
		}
		if v != 0 {
			buf = appendFieldVarint(buf, 4, v)
		}
	}
	if len(f.Payload) > 0 {
		buf = appendFieldBytes(buf, 5, f.Payload)
	}
	return buf, nil
}

func decodeFrame(data []byte) (*PortMappingFrame, error) {
	f := &PortMappingFrame{}
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
		case 1, 2, 3, 4:
			if wireType != 0 {
				return nil, fmt.Errorf("frame field %d: expected varint, got wire type %d", fieldNum, wireType)
			}
			v, n := decodeVarint(data[pos:])
			if n == 0 {
				return nil, fmt.Errorf("bad frame field %d", fieldNum)
			}
			pos += n
			s := strconv.FormatUint(v, 10)
			switch fieldNum {
			case 1:
				f.SessionID = s
			case 2:
				f.RuleID = s
			case 3:
				f.StreamID = s
			case 4:
				f.Type = frameTypeName(v)
			}
		case 5:
			b, n, err := decodeBytesField(data[pos:], wireType)
			if err != nil {
				return nil, err
			}
			pos += n
			f.Payload = b
		default:
			n, err := skipField(data[pos:], wireType)
			if err != nil {
				return nil, err
			}
			pos += n
		}
	}
	if f.Type == "" {
		f.Type = TypeConnect
	}
	return f, nil
}

func frameTypeValue(t FrameType) (uint64, error) {
	switch t {
	case "", TypeConnect:
		return 0, nil
	case TypeData:
		return 2, nil
	case TypeFin:
		return 1, nil
	case TypeSynAck:
		return 3, nil
	case TypeDataAck:
		return 4, nil
	default:
		return 0, fmt.Errorf("unknown frame type %q", t)
	}
}

func frameTypeName(v uint64) FrameType {
	switch v {
	case 0:
		return TypeConnect
	case 1:
		return TypeFin
	case 2:
		return TypeData
	case 3:
		return TypeSynAck
	case 4:
		return TypeDataAck
	default:
		return FrameType(fmt.Sprintf("UNKNOWN_%d", v))
	}
}

// NewConnect builds a CONNECT frame payload.
func NewConnect(targetHost string, targetPort int) []byte {
	// Keep the official client's JSON key order for byte-for-byte comparison.
	return []byte(fmt.Sprintf(`{"target_host":"%s","target_port":%d,"version":1}`, targetHost, targetPort))
}

// NewSynAck builds a SYN_ACK frame payload.
func NewSynAck() []byte {
	return []byte(`{"ok":true,"version":1}`)
}

// protobuf helpers

func appendFieldString(buf []byte, fieldNum uint64, s string) []byte {
	buf = appendVarint(buf, (fieldNum<<3)|2)
	buf = appendVarint(buf, uint64(len(s)))
	return append(buf, s...)
}

func appendFieldVarint(buf []byte, fieldNum, value uint64) []byte {
	buf = appendVarint(buf, (fieldNum<<3)|0)
	return appendVarint(buf, value)
}

func appendFieldBytes(buf []byte, fieldNum uint64, b []byte) []byte {
	buf = appendVarint(buf, (fieldNum<<3)|2)
	buf = appendVarint(buf, uint64(len(b)))
	return append(buf, b...)
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

func decodeStringField(data []byte, wireType uint64) (string, int, error) {
	if wireType != 2 {
		return "", 0, fmt.Errorf("string field: expected wire type 2, got %d", wireType)
	}
	b, n, err := decodeBytesField(data, 2)
	return string(b), n, err
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
