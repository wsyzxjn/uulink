# uulink

Standalone two-endpoint TCP port forwarding client for NetEase UU Remote — no
GUI client required in the final target.

Inspired by [tslink](https://github.com/saltedfishclub/tslink), this tool connects to the UU Remote network and provides TCP port forwarding between your local machine and a remote device.

## Final Goal

The completed product runs the same `uulink` binary on two devices. The two
processes establish a UU Remote WebRTC/PM data plane and support arbitrary TCP
port mappings in either direction:

```text
Device A local listener -> service reachable by Device B
Device B local listener -> service reachable by Device A
```

The full scope, acceptance tests, and implementation roadmap are documented in
[workspace/uulink-final-goal.md](workspace/uulink-final-goal.md).

## Status

**The final two-uulink mode is live-verified.** Current status:

- [x] REST API authentication (X-Param-SIGN algorithm fully reverse-engineered)
- [x] HMAC-SHA256 signing with all 13 header parameters
- [x] **Live REST verification**: user/info ✓, device/list ✓ (QmQ/QWQ listed)
- [x] **Live room/create ✓**: returns signaling token + 3 gateways
- [x] socket.io signaling client (EIO=4 over WebSocket) — **live-verified**
  (namespace connect confirmed, server pushes received)
- [x] PortMappingFrame protobuf codec (reconstructed from binary analysis)
- [x] TCP tunnel with DATA/DATA_ACK flow control
- [x] WebRTC offer/answer/candidate plumbing (pion/webrtc)
- [x] WebRTC negotiation with a real remote peer (QWQ)
- [x] PortMappingFrame wire format confirmed against real traffic
- [x] End-to-end port forwarding test
- [x] Guest identity API (`/api/v1/guest/create`) live-verified
- [x] QR-code login bootstrap (`/api/v1/qrcode/gen/login`) live-verified
- [x] UULink controlled/server-side peer (answers a `soac` offer)
- [x] Symmetric PM tunnel with dynamic inbound target dialing
- [x] Multi-rule mapping configuration
- [x] Controller + controlled peer + WebRTC + PM tunnel integration test
  (bidirectional and concurrent)
- [x] **Real NetEase signaling two-device E2E**: Mac and QWQ each ran `uulink`,
  established WebRTC over real UU signaling, and passed bidirectional concurrent
  TCP port forwarding
- [x] QR-code login bootstrap, status polling, and JWT exchange

The 2026-08-31 physical-device acceptance used:

```text
Mac 127.0.0.1:18080 -> QWQ 127.0.0.1:8081
QWQ 127.0.0.1:18081 -> Mac 127.0.0.1:8080
```

Both directions passed eight concurrent HTTP requests and returned the target
service on the opposite device.

## Live Test Results (2026-08-29)

```
$ ./uulink -list
DEVICE_ID                NAME             STATUS         PLAT     VERSION
aeawqa5txeafoxl4         QmQ              CONNECTED      4        4.38.0
aeawn7l56uabjgfc         QWQ              DISCONNECTED   1        2.2.2.2400

$ ./uulink -local 19090 -remote-port 80
creating room (server mode)...
signaling_server=wss://sig-3207-z2.nrd.nie.163.com/ (3 gateways)
[signaling] connected, sid=2oqvbOJnIWQIGc0oFjot, pingInterval=15s
[signaling] namespace connected: {"sid":"54b668b86d-txgbq:..."}
[signaling] bmsg_push: {"type":"device_info_changed",...}
[tunnel] uulink-19090-80: listening on 127.0.0.1:19090 -> 127.0.0.1:80

$ ./uulink -device aeawn7l56uabjgfc -local 19091 -remote-port 3389
join room: code 2001: 被控设备不在线，无法发起远控  (QWQ offline, expected)
```

Room create response fields (live-captured):
- `token` — X-NRD-AUTH for the signaling WebSocket
- `signaling_server` + `signaling_list` — 3 gateway URLs
- `report_url` / `report_token` — relay reporting (x-report-token header)
- `max_reconnect_delta`, `ws_connect_timeout_ms`, `streamer_retry_delta_ms`

Socket.io signaling state machine (from binary):
`peerOffer` → `peerAnswer` → `exchangeCandidate` → `peerConnected` / `peerError`

## Guest Identity

UU Remote has a real guest identity path, but it is not a full no-login
controller path:

- `POST /api/v1/guest/create` succeeds without the configured JWT and returns
  `guest_id` plus a guest JWT.
- That guest JWT is rejected by `/api/v1/user/info` and `/api/v1/device/list`
  with business code `1002` (`查询对象不存在`).
- `POST /api/v1/guest/room/create` succeeds and returns the same signaling
  token / gateway structure as the normal room-create flow.
- `POST /api/v1/guest/share/info` succeeds and returns `connect_id` and
  `connect_code`.

So the guest flow is best understood as a guest room/share flow. The official
client still requires a logged-in user on the controller side before it will
start remote assistance.

Additional live result: the official client can generate the remote-assistance
temporary verification code while logged out. A guest identity cannot use that
code to join as the controller; the controller side still needs a valid login.

Official public documentation agrees with this boundary: the UU Remote "lite"
page describes the no-install/no-login build as a Windows controlled endpoint
only, and explicitly says it cannot initiate remote control. The official help
article for assisting another computer also lists both endpoints logging in as
step one.

## Architecture

```
uulink (local)                         UU Remote Server (remote device)
    │                                        │
    ├─ REST API ──────────────────────────────┤  room/join
    ├─ socket.io signaling (WSS) ────────────┤  SDP/ICE exchange
    ├─ WebRTC data channel ──────────────────┤  P2P or TURN relay
    │    └─ FILE_DATA_CHANNEL: gvpb.Message ─┤  TCP stream multiplexing
    │                                        │
    └─ local TCP listener ─── tunnel ───── remote TCP connect
```

## Usage

Current usage supports both sides with UULink. The controller side joins the
device running `-serve`; either side can expose a local listener that maps to a
target reachable by the other side.

```bash
# Build
go build -o uulink ./cmd/uulink/

# Build the Windows binary for the second device
GOOS=windows GOARCH=amd64 go build -o uulink.exe ./cmd/uulink

# Package the Windows binary and example config
zip -j workspace/uulink-windows-amd64.zip uulink.exe config.example.json

# Create config (see config.example.json)
cp config.example.json config.json
# Edit config.json with your credentials

# List devices
./uulink -list

# Generate an official QR-code login URL
./uulink -login-qrcode

# Generate a scannable QR code and poll for login confirmation
workspace/login-qrcode.sh

# The QR code expires server-side; the script refreshes it every four minutes.

# Extract a JWT after the official app logs in and opens a WebView page
workspace/extract_jwt_from_cache.py
# The official UURemote client must be logged in before this can succeed.

# Device B: create a room, answer WebRTC, and expose 18081 -> A-side target
./uulink -serve -local 18081 -remote-host 127.0.0.1 -remote-port 8080

# Device A: join B and expose 18080 -> B-side target
./uulink -device <B-device-id> -local 18080 -remote-host 127.0.0.1 -remote-port 8081
```

When connecting to an official client instead of a UULink server, pass its
registered numeric `-rule-id`. For UULink-to-UULink mappings, rule IDs are
generated locally and the receiving side dials the target carried by the PM
CONNECT payload.

For a same-host smoke test with two configs, run:

```bash
go build -o uulink ./cmd/uulink
CONTROLLER_DEVICE=<server-device-id> workspace/two-device-e2e.sh
```

The script starts two local HTTP targets, one `-serve` process, one controller
process, and verifies both mapping directions with HTTP.

For the real final acceptance, run one binary on each physical device using
[workspace/two-device-remote.md](workspace/two-device-remote.md).

For same-host real-signaling debugging, use the room-file path instead. This
avoids the server-side restriction on joining a room by the same device ID:

```bash
go build -o uulink ./cmd/uulink
workspace/same-host-room-file-e2e.sh
```

The script starts the `-serve` side with `-room-file`, waits for that file,
starts the controller from the same room information, and concurrently verifies
multiple mapping rules in both directions. It requires a currently valid JWT in
`config.json`; it is a debugging gate for real NetEase signaling, not the
final two-device acceptance.

`workspace/fake-uulink-harness.py` can replace the binary when testing the
E2E script mechanics without NetEase signaling:

```bash
UULINK_BIN=workspace/fake-uulink-harness.py MAPPING_COUNT=3 CONCURRENT_CHECKS=6 \
  workspace/same-host-room-file-e2e.sh
```

## Config

```json
{
  "jwt": "your JWT token from UU Remote login",
  "client_id": "IOPlatformUUID of this machine",
  "device_id": "this device ID",
  "user_id": "your user ID",
  "mappings": [
    {
      "local_host": "127.0.0.1",
      "local_port": 18080,
      "remote_host": "127.0.0.1",
      "remote_port": 8080
    }
  ]
}
```

To extract these values from an existing UU Remote installation:
- JWT: `defaults read com.netease.uuremote` (look for token fields)
- client_id: `ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformUUID/{print $3}'`
- device_id / user_id: from the UU Remote device list API or app UI

## Project Structure

```
cmd/uulink/          CLI entry point
pkg/
  auth/              SIGN algorithm + header builder
  api/               REST API client
  signaling/         socket.io EIO=4 client
  proto/gvpb/        PortMappingFrame protobuf codec
  tunnel/            TCP port forwarding
proto/gvpb/          Proto definitions (reconstructed)
workspace/           Reverse engineering artifacts
doc/                 Analysis documentation
```

## How SIGN Works

The `X-Param-SIGN` header is `HMAC-SHA256(key, material)` in lowercase hex:

```
key      = "alWiSzXZTLu3WfFnw13uBru3"  (from NEShelter XOR 0x5A decode)

material = METHOD + PATH(?query)
         + sorted(x-param-*=value joined by &)
         + POST body (raw, no separator)
```

Verified against 10 unique captured samples (GET/POST, with/without query and body).
