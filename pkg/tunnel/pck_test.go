package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/user/uulink/pkg/proto/gvpb"
)

func TestBuildConnectPCKWrapsProtobufMessage(t *testing.T) {
	frame, err := BuildConnectPCK(5, "1788015422013002", "1", "127.0.0.1", 3389)
	if err != nil {
		t.Fatalf("build PCK CONNECT: %v", err)
	}
	if len(frame) < 28 {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}
	if !bytes.Equal(frame[:6], []byte("PCK\x02V3")) {
		t.Fatalf("unexpected PCK magic: %x", frame[:6])
	}
	if frame[8] != 0x51 {
		t.Fatalf("expected data frame type 0x51, got %#x", frame[8])
	}
	if sourceChan := binary.LittleEndian.Uint32(frame[16:20]); sourceChan != 4 {
		t.Fatalf("expected source channel 4, got %d", sourceChan)
	}
	if targetChan := binary.LittleEndian.Uint32(frame[20:24]); targetChan != 5 {
		t.Fatalf("expected target channel 5, got %d", targetChan)
	}

	payloadLen := int(binary.LittleEndian.Uint32(frame[24:28]))
	if payloadLen != len(frame)-28 {
		t.Fatalf("payload length mismatch: header=%d actual=%d", payloadLen, len(frame)-28)
	}

	appData := frame[28:]
	if !bytes.HasSuffix(appData, []byte{0x03, 0x00, 0x01, 0x00}) {
		t.Fatalf("missing AppData trailer: %x", appData)
	}

	ad, err := parseAppDataForTest(appData[:len(appData)-4])
	if err != nil {
		t.Fatalf("parse AppData: %v", err)
	}
	if ad.headerKind != 1 {
		t.Fatalf("expected AppData header kind 1, got %d", ad.headerKind)
	}
	if ad.appSeq == 0 {
		t.Fatal("AppData top-level sequence must be non-zero")
	}

	msg, err := gvpb.DecodeMessage(ad.payload)
	if err != nil {
		t.Fatalf("decode PM protobuf: %v", err)
	}
	if msg.PortMappingFrame == nil {
		t.Fatal("PM protobuf message has no PortMappingFrame")
	}
	framePM := msg.PortMappingFrame
	if framePM.RuleID != "1788015422013002" || framePM.StreamID != "1" || framePM.SessionID != SessionID {
		t.Fatalf("unexpected PM frame metadata: %+v", framePM)
	}
	if !bytes.Contains(framePM.Payload, []byte(`"target_host":"127.0.0.1","target_port":3389,"version":1`)) {
		t.Fatalf("unexpected CONNECT payload: %s", framePM.Payload)
	}
}

type testAppData struct {
	appSeq     uint64
	timestamp  uint64
	headerKind uint64
	payload    []byte
}

func parseAppDataForTest(data []byte) (*testAppData, error) {
	out := &testAppData{}
	pos := 0
	for pos < len(data) {
		tag, n := readUvarintForTest(data[pos:])
		if n == 0 {
			return nil, fmt.Errorf("short varint at offset %d", pos)
		}
		pos += n
		fieldNum := tag >> 3
		wireType := tag & 7
		switch fieldNum {
		case 1, 2:
			value, n := readUvarintForTest(data[pos:])
			if n == 0 {
				return nil, fmt.Errorf("short varint at offset %d", pos)
			}
			pos += n
			if fieldNum == 1 {
				out.appSeq = value
			} else {
				out.timestamp = value
			}
		case 3:
			header, n, err := readLenForTest(data[pos:], wireType)
			if err != nil {
				return nil, err
			}
			pos += n
			kind, err := parseHeaderKindForTest(header)
			if err != nil {
				return nil, err
			}
			out.headerKind = kind
		case 4:
			payload, n, err := readLenForTest(data[pos:], wireType)
			if err != nil {
				return nil, err
			}
			pos += n
			out.payload = payload
		default:
			return nil, fmt.Errorf("unsupported AppData field %d", fieldNum)
		}
	}
	return out, nil
}

func parseHeaderKindForTest(data []byte) (uint64, error) {
	pos := 0
	for pos < len(data) {
		tag, n := readUvarintForTest(data[pos:])
		if n == 0 {
			return 0, fmt.Errorf("short varint at offset %d", pos)
		}
		pos += n
		fieldNum := tag >> 3
		wireType := tag & 7
		if fieldNum == 1 && wireType == 0 {
			value, n := readUvarintForTest(data[pos:])
			if n == 0 {
				return 0, fmt.Errorf("short varint at offset %d", pos)
			}
			return value, nil
		}
		if wireType == 0 {
			_, n := readUvarintForTest(data[pos:])
			if n == 0 {
				return 0, fmt.Errorf("short varint at offset %d", pos)
			}
			pos += n
			continue
		}
		if wireType != 2 {
			return 0, fmt.Errorf("unsupported wire type %d", wireType)
		}
		_, n, err := readLenForTest(data[pos:], wireType)
		if err != nil {
			return 0, err
		}
		pos += n
	}
	return 0, fmt.Errorf("header kind missing")
}

func readUvarintForTest(data []byte) (uint64, int) {
	var value uint64
	for i := 0; i < len(data) && i < 10; i++ {
		b := data[i]
		value |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return value, i + 1
		}
	}
	return 0, 0
}

func readLenForTest(data []byte, wireType uint64) ([]byte, int, error) {
	if wireType != 2 {
		return nil, 0, fmt.Errorf("unsupported wire type %d", wireType)
	}
	length, n := readUvarintForTest(data)
	if n == 0 || int(length) > len(data)-n {
		return nil, 0, fmt.Errorf("bad length field")
	}
	return data[n : n+int(length)], n + int(length), nil
}
