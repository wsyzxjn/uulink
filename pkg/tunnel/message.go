package tunnel

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/user/uulink/pkg/proto/gvpb"
)

var msgSeqCounter atomic.Uint64

// nextSeq returns the next message sequence (official client starts low, e.g. 6).
func nextSeq() string {
	n := msgSeqCounter.Add(1)
	if n < 6 {
		n = 5 + n // first call returns 6
	}
	return strconv.FormatUint(n, 10)
}

// newConnectMsg builds the CONNECT/SYN Message.
func newConnectMsg(ruleID, streamID, host string, port int) ([]byte, error) {
	payload := gvpb.NewConnect(host, port)
	return buildMsg(ruleID, streamID, gvpb.TypeConnect, payload)
}

// newDataMsg builds a DATA Message.
func newDataMsg(ruleID, streamID string, payload []byte) ([]byte, error) {
	return buildMsg(ruleID, streamID, gvpb.TypeData, payload)
}

func newSynAckMsg(ruleID, streamID string, ok bool) ([]byte, error) {
	payload := gvpb.NewSynAck()
	if !ok {
		payload = []byte(`{"ok":false,"version":1}`)
	}
	return buildMsg(ruleID, streamID, gvpb.TypeSynAck, payload)
}

// newACKMsg builds an ACK Message.
func newACKMsg(ruleID, streamID string) ([]byte, error) {
	return buildMsg(ruleID, streamID, gvpb.TypeDataAck, nil)
}

// newFINMsg builds a FIN Message.
func newFINMsg(ruleID, streamID string) ([]byte, error) {
	return buildMsg(ruleID, streamID, gvpb.TypeFin, nil)
}

// buildMsg encodes the protobuf Message wire format.
func buildMsg(ruleID, streamID string, frameType gvpb.FrameType, payload []byte) ([]byte, error) {
	m := &gvpb.Message{
		Seq:       nextSeq(),
		Timestamp: fmt.Sprintf("%d", time.Now().Unix()),
		PortMappingFrame: &gvpb.PortMappingFrame{
			SessionID: SessionID,
			RuleID:    ruleID,
			StreamID:  streamID,
			Type:      frameType,
			Payload:   payload,
		},
	}
	out, err := m.Encode()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// decodeMsg parses a protobuf wire-format Message from the remote peer.
func decodeMsg(data []byte) (*gvpb.Message, error) {
	return gvpb.DecodeMessage(data)
}

// unused helper retained for potential JSON debugging
func _jsonDebug(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
