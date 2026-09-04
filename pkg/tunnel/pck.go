package tunnel

import (
	"encoding/binary"
	"strconv"
	"sync/atomic"
	"time"
)

// PCK.V3 + AppData wrapping for PM frames (reverse-engineered from official
// client captures, 2026-08-30):
//
//	PCK frame: "PCK\x02V3" | 02 00 | 0x51(data) | 00 00 01 | seq(4B LE) | chan(4B LE) | x(4B LE) | len(4B LE) | payload
//	payload = AppData protobuf | trailer 03 00 01 00
//	AppData: f1=app sequence, f2=timestamp, f3=header{1:kind, 2:metaJSON, 4:cap16}, f4=body
var pckSeqCounter atomic.Uint32
var pckAppSeqCounter atomic.Uint64

// capabilityBlob mirrors ConnectOptions field 11 (16 bytes).
var pckCapBlob = []byte{0x08, 0x06, 0x10, 0x02, 0x18, 0x01, 0x20, 0x02, 0x30, 0x02, 0x38, 0x02, 0x40, 0x02, 0x48, 0x01}

var pckMetaSeq atomic.Uint64

// buildPCKFrame wraps body in an AppData message inside a PCK.V3 data frame.
func buildPCKFrame(sourceChan, targetChan uint32, meta string, body []byte) []byte {
	var ad []byte // AppData protobuf
	ad = appendPBVarintField(ad, 1, nextPCKAppSeq())
	ad = appendPBVarintField(ad, 2, uint64(time.Now().UnixMilli()))
	var hdr []byte
	hdr = appendPBVarintField(hdr, 1, 1)
	if meta != "" {
		hdr = appendPBBytesField(hdr, 2, []byte(meta))
	}
	hdr = appendPBBytesField(hdr, 4, pckCapBlob)
	ad = appendPBBytesField(ad, 3, hdr)
	if len(body) > 0 {
		ad = appendPBBytesField(ad, 4, body)
	}
	// trailer seen on every captured frame
	ad = append(ad, 0x03, 0x00, 0x01, 0x00)

	seq := pckSeqCounter.Add(1)
	frame := []byte("PCK\x02V3")
	frame = append(frame, 0x02, 0x00, 0x51, 0x00, 0x00, 0x01)
	frame = binary.LittleEndian.AppendUint32(frame, seq)
	frame = binary.LittleEndian.AppendUint32(frame, sourceChan)
	frame = binary.LittleEndian.AppendUint32(frame, targetChan)
	frame = binary.LittleEndian.AppendUint32(frame, uint32(len(ad)))
	frame = append(frame, ad...)
	return frame
}

// nextPCKAppSeq returns the AppData top-level sequence. Captured frames show
// this field increasing independently of the PCK header sequence and the
// metadata sequence.
func nextPCKAppSeq() uint64 {
	return pckAppSeqCounter.Add(1)
}

// nextPCKMeta returns the {"seq":N} metadata used in channel registrations.
func nextPCKMeta() string {
	return `{"seq":` + strconv.FormatUint(pckMetaSeq.Add(1), 10) + `}`
}

// buildRegistrationFrame replicates the official client's channel registration:
// PCK data frame with chan=<next chan-1>, x=<target chan>, AppData kind 3 with
// {"seq":N} meta and capability blob.
func buildRegistrationFrame(targetChan uint32) []byte {
	return buildPCKFrame(targetChan-1, targetChan, nextPCKMeta(), nil)
}

// buildSessionSetup replicates the two session-setup frames (kind 1 and 2).
func buildSessionSetup(kind uint64) []byte {
	return buildPCKFrame(uint32(kind-1), uint32(kind), "", nil)
}

// Exported builders for the PCK sweep in main.

// BuildSessionSetup returns a PCK session-setup frame for kind (1 or 2).
func BuildSessionSetup(kind uint64) []byte { return buildSessionSetup(kind) }

// BuildRegistration returns a channel-registration frame for targetChan.
func BuildRegistration(targetChan uint32) []byte { return buildRegistrationFrame(targetChan) }

// BuildConnectPCK wraps the PM CONNECT protobuf in a PCK frame on targetChan.
func BuildConnectPCK(targetChan uint32, ruleID, streamID, host string, port int) ([]byte, error) {
	payload, err := newConnectMsg(ruleID, streamID, host, port)
	if err != nil {
		return nil, err
	}
	sourceChan := targetChan
	if targetChan > 0 {
		sourceChan = targetChan - 1
	}
	return buildPCKFrame(sourceChan, targetChan, nextPCKMeta(), payload), nil
}

// BuildPMFramePCK wraps an already-encoded PM protobuf Message in a PCK.V3
// frame on targetChan.
func BuildPMFramePCK(targetChan uint32, msg []byte) []byte {
	sourceChan := targetChan
	if targetChan > 0 {
		sourceChan = targetChan - 1
	}
	return buildPCKFrame(sourceChan, targetChan, nextPCKMeta(), msg)
}

// protobuf helpers (local copies to avoid importing appdata)

func appendPBVarintField(buf []byte, fieldNum, value uint64) []byte {
	buf = appendPBVarint(buf, fieldNum<<3)
	return appendPBVarint(buf, value)
}

func appendPBBytesField(buf []byte, fieldNum uint64, value []byte) []byte {
	buf = appendPBVarint(buf, (fieldNum<<3)|2)
	buf = appendPBVarint(buf, uint64(len(value)))
	return append(buf, value...)
}

func appendPBVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}
