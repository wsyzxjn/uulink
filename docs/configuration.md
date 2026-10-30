# Advanced configuration

Existing configuration files continue to work. Add only the settings you need to
your local `config.json`; restarting uulink applies them to new connections.
An [example](../config.advanced.example.json) shows the available groups. It does
not contain login credentials and should be merged with your existing file.

## Client compatibility

| Setting | Purpose |
| --- | --- |
| `version_name` | Client version used by REST requests, the User-Agent and the connection handshake |
| `version_code` | Build number used by REST requests and the User-Agent |
| `streamer_version` | Streaming protocol version used by signaling and relay reports |
| `platform` | `1` for the Windows compatibility profile, `4` for macOS; omitted/`0` selects Windows on Windows and macOS elsewhere |
| `api_base_url` | Alternate API endpoint, normally left unset |

The precedence for versions is environment, then configuration, then the bundled
compatibility profile. The environment variables are `UULINK_CLIENT_VN`,
`UULINK_CLIENT_VC`, and `UULINK_STREAMER_VERSION`. All connection paths, including
reconnections and additional pooled sessions, use the same resolution rules.

The bundled defaults remain macOS `4.38.0` / build `616`, Windows `4.38.3` / build
`9325`, and streamer `V4.5.3`. These are known compatibility baselines, not a claim
that they are the latest official versions. A newer version string alone does
not implement new upstream protocol features.

`client_profile` can override `package_name`, `channel`, `language`, `country`,
`release`, `operator`, `user_agent_os`, `user_agent_suffix`, and
`websocket_user_agent`. The HTTP User-Agent is generated from the resolved version
and build number. `signing_key` overrides the API protocol signing material for
both normal API calls and relay reports; it is normally left unset. It is not a
replacement for the account's login token. Profile values are not shared with a
peer or included in published share configurations.

## Device registration

Optional `devices.mac` and `devices.windows` objects override registration
metadata. Supported keys are `os`, `memory`, `cpu`, `video` (a string array),
`resolution`, `screen`, `system_name`, `system_version`, `model`,
`model_identifier`, `model_number`, `base_board`, and `dpi`.

Omitted values keep the compatibility template. The macOS template describes an
M4 Mac; the accountless Windows template describes virtual hardware. These are
explicit upstream registration profiles, not hardware detection results.
Registration follows the selected `platform` in both `serve` and accountless
`share serve`, including login bootstrap and pooled sessions:

| Platform | Registration endpoint | Controllability endpoint |
| --- | --- | --- |
| `1` (Windows) | `/api/v1/device/windows/init` | `/api/v1/device/controllable` |
| `4` (macOS) | `/api/v1/device/macos/init` | `/api/v1/device/mac_controllable` |

Guest sessions carry their registered platform explicitly, so later requests do
not guess the platform from a client ID or the host OS. Both platform flows have
been checked against the official registration, guest and room APIs.

Unbound identities are saved with `unbound_platform`. Changing platforms creates
a fresh compatible client/device identity; a share's connect ID can therefore
change. Existing Windows `MG-` identities are reused when Windows stays selected.
The ordinary `serve` command also saves the identity returned by registration.
Failed registrations do not replace saved IDs. Device IDs, client IDs and the
derived MAC remain unique to the installation; metadata cannot replace them.
`hostname` still controls the name.

## Network tuning

All fields below belong inside `network`. Units are part of each field name.
Omitted numeric fields, or `0`, select their defaults. Negative and excessive
values are rejected before starting a connection. Login/config saves may make
resolved network defaults explicit in the saved file.

| Field | Default | Accepted nonzero values |
| --- | --- | --- |
| `api_timeout_seconds` | 60 | 1–3600 |
| `signaling_timeout_seconds` | 10 | 1–3600 |
| `control_ack_timeout_seconds` | 15 | 1–3600 |
| `transport_timeout_seconds` | 30 | 1–3600 |
| `connect_timeout_seconds` | 10 | 1–3600 |
| `half_close_timeout_seconds` | 60 | 1–86400 |
| `keepalive_seconds` | 30 | 1–3600 |
| `udp_buffer_bytes` | 4194304 | 1–67108864 |
| `sctp_receive_buffer_bytes` | 4194304 | 1–67108864 |
| `sctp_min_cwnd_bytes` | 131072 | 1–16777216 |
| `sctp_rto_max_ms` | 1500 | 1–60000 |
| `file_buffer_bytes` | 8388608 | 65536–67108864 |
| `file_buffer_wait_seconds` | 30 | 1–3600 |
| `max_in_flight` | 128 | 1–4096 frames per TCP stream |
| `session_limit` | 16 | 1–64 total sessions, including the primary |

`api_timeout_seconds` controls the API HTTP client. Relay reports additionally
retain a 10-second request deadline. `signaling_timeout_seconds` covers the
WebSocket handshake, initial gateway packet and namespace connection.
`transport_timeout_seconds` covers readiness of primary and pooled data channels.
`connect_timeout_seconds` and `half_close_timeout_seconds` apply to forwarded TCP
connections. OS socket buffer sizes remain subject to the OS's own limits.

`stun_servers` controls STUN discovery on the serving peer:

- Omitted or `null`: use automatic discovery. When answering a new connection,
  prefer the gateway's `be-controlled` ICE metadata for that controller, then
  the `room_info` ICE list. If neither supplies valid STUN URLs, use the bundled
  compatibility addresses as a last resort.
- A nonempty list, such as `["stun:your-stun-host.example:3478"]`: use exactly
  this list, overriding discovery and the fallback.
- `[]`: disable STUN queries, including dynamic discovery and the fallback.

The gateway list is held only in the current peer's memory and refreshed by new
signaling metadata. It is not persisted to the config and does not require a
separate API login or periodic polling. Updates are applied when creating a new
peer connection; existing transfers are not interrupted to change their STUN
servers. A control event with mismatched connection IDs is not used for the offer.

Logs report `controlled STUN source=be-controlled`, `room_info`, `config` or
`fallback`, plus the server count. TURN entries, credentials and malformed URLs
are excluded from this STUN list. Controller TURN discovery continues to use its
upstream control reply. STUN discovery does not add UDP port forwarding.

If an earlier config save wrote the old STUN addresses explicitly, set
`network.stun_servers` back to `null` to enable automatic discovery. Config saves
now preserve `null` as automatic and `[]` as disabled.

The local integration suite verifies that a serving peer sends actual STUN
binding requests to a URL delivered by a fake gateway, then carries TCP data
through the established WebRTC connection. Production gateway validation is a
separate opt-in test; local tests do not establish acceptance of the current
production event payload.

Relay diagnostics: warnings from Pion's TURN client, such as a rejected
allocation refresh, a failed channel bind or a full relay receive buffer, are
logged as `turnc WARNING:` lines next to uulink's own output. `-log-level error`
hides them. Pion's `PION_LOG_<LEVEL>=<scope,...|all>` variables still override
each scope, for example `PION_LOG_DEBUG=ice,turnc` to trace candidate checks and
TURN refreshes. The periodic `connection status` line reports the selected
candidate pair, including the relay address, RTT and byte counts.

To allow a target above 16 sessions, set `network.session_limit` on both ends,
then choose a target with `sessions`/`-sessions`. Increasing the limit alone does
not create more sessions. The default automatic target stays 4 (or the lower
configured limit). Remote expansion requests cannot exceed the serving endpoint's
target or the absolute resource guard of 64 sessions. Older peers keep their own
limits and may return fewer sessions.

## Developer notes: protocol constants and experiments

The connection handshake is encoded from protobuf fields in
`pkg/proto/gvpb/handshake.go`. Known device/version fields are supplied per peer;
message timestamps and sequences are generated at runtime. The previous complete
capture is retained only as a regression fixture. Capability overrides are local
to a peer and do not affect other connections.

Unidentified media enum values are deliberately preserved in that compatibility
profile. In particular, ConnectOptions field 8 is still `4`: its meaning is not
established, so it must not be inferred from the host OS. Protocol enums, field
numbers, channel labels, framing markers and the mapping namespace `1` are
compatibility constants. The mapping namespace is scoped to a peer; rule and
stream IDs distinguish connections within it. Socket.IO ACK IDs are allocated
dynamically, including the two IDs needed for the control reply sequence.

Resource guards (response size limits, queue bounds and the maximum supported
session count) remain bounded. TCP forwarding is still TCP-only. Minecraft LAN
discovery retains the protocol's multicast address/port. These are not arbitrary
installation-specific values to replace automatically.

Experimental commands require `go build -tags experiments ./cmd/uulink`.
`-pck-sweep` retains its explicitly documented experimental framing and reuses
the common capability encoder. `-mixkcp` now requires `-mixkcp-frame PATH`, where
PATH contains a complete encoded UDP datagram supplied by the operator. A sample
session header or first-byte value is never substituted automatically. The tool
does not construct ciphertext from plaintext, and a reply is not classified as
SYN_ACK from an undocumented byte value. This is a raw replay diagnostic, not
working UDP port forwarding; upstream acceptance is not guaranteed.

Relevant offline checks:

```sh
go test -race ./...
go test -race -tags integration ./...
go test -race -tags 'integration experiments' ./...
go vet ./...
go vet -tags experiments ./cmd/...
```

Integration tests use local fake gateways and loopback peers. They establish
configuration propagation, framing compatibility and local TCP forwarding, not
current acceptance by the production UU service.
