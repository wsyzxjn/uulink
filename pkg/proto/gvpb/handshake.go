package gvpb

// DefaultMappingSession identifies the port-mapping namespace inside one peer
// connection, not a global connection ID. Rule/stream IDs provide multiplexing.
// The official protocol uses namespace 1; inventing a new value breaks interop.
const DefaultMappingSession = "1"

// DefaultCapabilities encodes the negotiated feature schema observed in the
// compatible official client. Unknown enum meanings remain documented by field
// number instead of being misrepresented as host hardware capabilities.
func DefaultCapabilities() []byte {
	var out []byte
	for _, field := range [][2]uint64{{1, 6}, {2, 2}, {3, 1}, {4, 2}, {6, 2}, {7, 2}, {8, 2}, {9, 1}} {
		out = appendFieldVarint(out, field[0], field[1])
	}
	return out
}

// ConnectOptions builds the compatibility profile from protobuf fields. The
// media options retain the captured defaults because these fields also appear
// on data-only connections; changing their semantics needs upstream evidence.
// Identified device/version fields and feature overrides are supplied per peer.
// Field 8 remains 4: its meaning is not established, so it is not inferred from GOOS.
func ConnectOptions(deviceID, version string, capabilities []byte) []byte {
	if capabilities == nil {
		capabilities = DefaultCapabilities()
	}
	resolution := appendFieldVarint(nil, 1, 5120)
	resolution = appendFieldVarint(resolution, 2, 2880)
	video := appendFieldVarint(nil, 1, 2)
	video = appendFieldVarint(video, 2, 6)
	video = appendFieldVarint(video, 4, 1)
	video = appendFieldBytes(video, 5, resolution)
	video = appendFieldBytes(video, 6, nil)
	video = appendFieldVarint(video, 7, 1)
	video = appendFieldVarint(video, 8, 30000000)
	video = appendFieldVarint(video, 11, 60)
	out := appendFieldVarint(nil, 1, 1)
	out = appendFieldVarint(out, 2, ^uint64(0))
	out = appendFieldBytes(out, 3, video)
	for _, mode := range [][2]uint64{{2, 1}, {2, 3}, {1, 1}, {1, 3}} {
		codec := appendFieldVarint(nil, 1, 120)
		codec = appendFieldVarint(codec, 2, mode[0])
		codec = appendFieldVarint(codec, 3, 3840)
		codec = appendFieldVarint(codec, 4, 2160)
		codec = appendFieldVarint(codec, 5, mode[1])
		out = appendFieldBytes(out, 4, codec)
	}
	out = appendFieldBytes(out, 6, appendFieldVarint(append([]byte{}, resolution...), 3, 120))
	out = appendFieldBytes(out, 7, resolution)
	out = appendFieldVarint(out, 8, 4)
	out = appendFieldBytes(out, 9, []byte(deviceID))
	out = appendFieldVarint(out, 10, 1)
	out = appendFieldBytes(out, 11, capabilities)
	return appendFieldBytes(out, 12, []byte(version))
}

func ControlHandshake(seq, timestamp uint64, capabilities []byte) []byte {
	if capabilities == nil {
		capabilities = DefaultCapabilities()
	}
	inner := appendFieldBytes(nil, 4, capabilities)
	var out []byte
	if seq != 0 {
		out = appendFieldVarint(out, 1, seq)
	}
	out = appendFieldVarint(out, 2, timestamp)
	return appendFieldBytes(out, 3, inner)
}

func TextHandshake(seq, timestamp uint64) []byte {
	out := appendFieldVarint(nil, 1, seq)
	out = appendFieldVarint(out, 2, timestamp)
	// Field 13 contains the packed list of the two supported text message types.
	return appendFieldBytes(out, 13, appendFieldBytes(nil, 1, []byte{1, 2}))
}
