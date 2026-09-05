# uulink

uulink is a lightweight TCP port forwarding tool built on the NetEase UU Remote network. It establishes stable point-to-point (P2P) TCP tunnels between devices across private networks without requiring the official GUI client on target machines.

## Use Cases

- Remote administration and development: Direct access to SSH, Remote Desktop (Windows RDP / VNC), or VS Code Remote across NATs and firewalls.
- Private network service access: Connect to private NAS web dashboards, databases, internal APIs, or file shares.
- Game server hosting: Share locally hosted game servers (such as Minecraft or Palworld) with friends without public IP addresses or router port forwarding.
- Headless server deployment: Minimal CPU and memory footprint, suitable for long-running services on headless Linux servers, mini PCs, and workstations.

## Key Features

- Headless CLI: Single self-contained binary, no desktop environment or graphical interface required.
- P2P direct connection with NAT traversal: Automatically prioritizes direct peer-to-peer tunnels, falling back to official relay nodes when direct traversal is restricted.
- Bidirectional multi-port forwarding: Forward ports in both directions over a single session (controller to server and server to controller).
- Batch mapping rules: Define multiple local-to-remote port mappings in a configuration file for instant batch activation.
- Headless account login: Prints an official login link to the terminal for you to open or scan on the UU Remote mobile client, then writes the resulting credentials into the configuration file. (No QR image is rendered; the link itself is printed.)
- Share code mode: Connect using temporary remote-assistance share codes without requiring devices to belong to the same account.
- Cross-platform: Runs on macOS, Linux, and Windows.
- Container-ready: Multi-architecture Docker images (`linux/amd64`, `linux/arm64`) published by CI for headless deployments.

## Quick Start

### 1. Download or Build the Binary

Download pre-compiled binaries from the Releases page, or compile from source:

```bash
# Build for the current platform
go build -o uulink ./cmd/uulink/

# Cross-compile for Windows from macOS or Linux
GOOS=windows GOARCH=amd64 go build -o uulink.exe ./cmd/uulink
```

### 2. Initialize Configuration

`uulink` creates `config.json` with a fresh client identity on its first run, so
no manual setup is needed to get started.

[config.example.json](config.example.json) documents every supported field and is
useful as a reference when you want to pre-declare mappings or a security policy.
Copy it only for those fields — its `jwt`, `client_id`, `device_id`, and `user_id`
entries are placeholders, and leaving them in place makes account commands fail
with `code 1001: 无效的请求参数` until the login step below overwrites them.

### 3. Log In to Your Account

Request the login QR code:

```bash
./uulink -login-qrcode
```

On a config that has never been used, uulink registers a device identity with UU
Remote first and stores it, because the login handshake has to identify this
machine. That happens automatically and only once.

The terminal will display a login QR code URL. Open or scan this link on your mobile client to authorize the login. The credentials will be saved directly to `config.json`.

If credentials expire later, refresh them with:

```bash
./uulink -refresh-login
```

### 4. List Registered Devices

List all devices registered under your account:

```bash
./uulink -list
```

Example output:

```text
DEVICE_ID                NAME             STATUS         PLAT     CLIENT_ID    VERSION
--------                 ----             ------         ----     ---------    -------
aeawqa5txeafoxl4         MyMac            CONNECTED      4                     4.38.0
aeawn7l56uabjgfc         HomePC           CONNECTED      1                     2.2.2.2400
```

Note the `DEVICE_ID` of the target machine you want to connect to. The
`CLIENT_ID` column is normally blank because the device listing API does not
return that field.

## Usage

### Method 1: Same-Account Device Pairing (Recommended)

Use this method when both machines are registered under the same UU Remote
account. Both endpoints must be logged in; `-serve` on a config without
credentials fails with `code 1001: 无效的请求参数`.

1. Start the server on the target (controlled) machine:

```bash
./uulink -serve
```

2. Connect from the client (controller) machine and map a port:

For example, to map remote Windows Remote Desktop (port 3389) to local port 13389:

```bash
./uulink -device <TARGET_DEVICE_ID> -local 13389 -remote-port 3389
```

Once connected, point your RDP client to `127.0.0.1:13389` to reach the remote desktop.

Similarly, to forward an SSH service:

```bash
./uulink -device <TARGET_DEVICE_ID> -local 2222 -remote-port 22
```

You can also forward consecutive port ranges or use the compact `-mapping` syntax:

```bash
# Map a port range 1-to-1 (e.g. 6 ports: 9000->8000, 9001->8001, ..., 9005->8005):
./uulink -device <TARGET_DEVICE_ID> -local 9000-9005 -remote-port 8000-8005

# Or with compact mapping flag:
./uulink -device <TARGET_DEVICE_ID> -mapping 9000-9005:8000-8005
```

### Method 2: Batch Mapping via Configuration File

When managing multiple forwarded ports, specify them in the `mappings` section of `config.json`:

```json
{
  "mappings": [
    {
      "local_port": 13389,
      "remote_port": 3389
    },
    {
      "local_port": "9000-9005",
      "remote_port": "8000-8005"
    },
    {
      "range": "7000-7002:6000-6002"
    }
  ]
}
```

Start the endpoints without passing port flags:

- Target machine: `./uulink -serve`
- Client machine: `./uulink -device <TARGET_DEVICE_ID>`

All configured ports will be mapped simultaneously.

### Method 3: Temporary Connection via Share Code (Guest Mode)

Use this method when machines belong to different accounts or for temporary access without binding the target device to your account. The target machine does not need to be logged in.

1. Start the assistance service on the target machine:

```bash
# Start an unbound guest server (no login required on this machine)
./uulink -unbound-guest-serve -sessions 1 -local 19081 -remote-port 18090
```

With `-sessions 1` the terminal displays one `connect_id` and an 8-character
`connect_code`:

```text
INFO guest share ready: connect_id=266444253 connect_code=6W44YBPL
```

The default pooled server (`-sessions 4`) instead opens one room per session and
prints the whole set on a single line, for direct use as flag values:

```text
INFO multi-session guest shares ready (4 sessions): -share-id 266444253,266444254,... -share-code 6W44YBPL,7X55ZCQM,...
```

2. Connect from the controlling machine using your credentials and the share code:

```bash
./uulink -share -share-id 266444253 -share-code 6W44YBPL -local 19090 -remote-port 18091
```

Once connected, bidirectional port forwarding between the two endpoints is active immediately.

The controller must be logged in. `-share-guest`, which joins with an ephemeral
guest identity so that neither side needs an account, is rejected by the API —
see [Known Issues](#known-issues).

### Method 4: Fixed Custom Verification Code Mode

Use this method when you want to establish access using a static, memorable
password rather than temporary random codes. The server side needs no account: a
missing `config.json` is created automatically with a stable client identity.
The connecting side, however, must be logged in: `-custom-connect` falls back to
an ephemeral guest identity when the config has no `jwt`, and the API rejects
guest identities on share joins (see [Known Issues](#known-issues)).

1. Start the server with a custom code (8-16 alphanumeric characters containing both letters and digits):

```bash
./uulink -custom-serve -custom-code MyPass123 -local 19081 -remote-port 18090
```

The terminal will display the assistance connect ID:

```text
INFO custom assistance ready: connect_id=266444253 custom_code=MyPass123
INFO client command: uulink -custom-connect 266444253 -custom-code MyPass123
```

If `-custom-code` is omitted, `uulink` generates a compliant code and prints it. The server saves its device identity, connect ID, and custom code to `config.json`, so restarting it keeps the same connect ID and code. The primary identity stays persistent even when extra relay sessions are created automatically. A pooled `-unbound-guest-serve` uses temporary identities instead.

2. Connect from the client using the connect ID and custom code:

```bash
./uulink -custom-connect 266444253 -custom-code MyPass123 -local 19090 -remote-port 18091
```

You can also specify `share_id` and `custom_code` in `config.json` for one-command startup:

```json
{
  "share_id": "266444253",
  "custom_code": "MyPass123",
  "mappings": [
    { "local_port": 19090, "remote_port": 18091 }
  ]
}
```

### Method 5: Remote Configuration Distribution (tslink-Compatible Zero-Config Mode)

Use this method for zero-friction distribution to friends or community players. The client fetches share credentials and mapping rules from an HTTP(S) URL (or a local file path).

The client joins with its own account when `config.json` contains a `jwt`, and
otherwise falls back to an ephemeral guest identity. Only the logged-in variant
works: the API does not let guest identities join shares (see
[Known Issues](#known-issues)), so recipients of a distributed client still need
to log in once, even though the machine being shared does not.

1. Publish or host a remote JSON configuration (e.g. on a web server, Cloudflare Worker, or GitHub Gist):

```json
{
  "share_id": "266444253",
  "share_code": "6W44YBPL",
  "mappings": [
    { "local_port": 25565, "remote_port": 25565 }
  ],
  "transport": "auto",
  "lan_motd": "Minecraft Server via uulink",
  "lan_port": 25565
}
```

Use `custom_code` instead of `share_code` when the server runs in custom-code mode. `transport` may be `relay` to require a TURN relay on every client. When `lan_motd` is set, the client announces the first forwarded port as a Minecraft LAN server.

The server can push the current share details to a webhook each time it starts using `-publish-url`; the webhook receives the same JSON document shown above:

```bash
./uulink -unbound-guest-serve -publish-url "https://example.com/sync" -publish-secret "mysecret" -mapping 25565:25565
```

2. Connect from the client using the configuration URL:

```bash
./uulink -config-url https://example.com/room.json
```

Or build a dedicated zero-argument client binary with the URL embedded via ldflags:

```bash
go build -ldflags="-X main.DefaultConfigURL=https://example.com/room.json" -o mc-link ./cmd/uulink
```

Users can simply run `./mc-link` without passing any arguments; a `config.json` with a random client identity is created next to the binary on first start.

## Docker

Multi-architecture images (`linux/amd64`, `linux/arm64`) are built and published by CI to this repository's GitHub Container Registry:

```bash
# Currently the only published moving tag (see the note below):
docker pull ghcr.io/wsyzxjn/uulink:edge
```

Available tags: `latest` and semantic versions (`1.2.3`, `1.2`, `1`) from `v*` releases, `edge` from the `main` branch, and `sha-<commit>` for every build.

> **No release has been published yet.** Until a `v*` tag runs the release
> workflow, only `edge` and `sha-<commit>` exist, and pulling `latest` fails.
> Use `ghcr.io/wsyzxjn/uulink:edge` (or set `UULINK_IMAGE` for Compose) in the
> meantime.

### Run

The image sets `WORKDIR /data`, so the default `-config` path resolves to `/data/config.json`. Mount a volume there to persist credentials and the accountless device identity across restarts:

```bash
docker volume create uulink-data

# Log in once (interactive terminal required for the QR code)
docker run --rm -it --network host -v uulink-data:/data ghcr.io/wsyzxjn/uulink:edge -login

# Then run the forwarder
docker run -d --name uulink --restart unless-stopped \
  --network host --hostname uulink-docker \
  -v uulink-data:/data \
  ghcr.io/wsyzxjn/uulink:edge -device TARGET_DEVICE_ID -local-host 0.0.0.0 -mapping 25565:25565
```

Replace `TARGET_DEVICE_ID` with the ID of a remote device running `uulink -serve`. Use `-list` to find device IDs.

Or use the bundled `docker-compose.yml`, which defaults to the published image:

```bash
docker compose pull
UULINK_DEVICE=TARGET_DEVICE_ID docker compose up -d

# Build from source instead of pulling
UULINK_DEVICE=TARGET_DEVICE_ID docker compose up -d --build

# Pin a specific tag
UULINK_DEVICE=TARGET_DEVICE_ID UULINK_IMAGE=ghcr.io/wsyzxjn/uulink:0.1.1 docker compose up -d
```

### Deployment notes

- **Networking:** `--network host` (Linux) lets WebRTC ICE see the real interface addresses, which keeps far more sessions on a direct P2P path instead of falling back to a TURN relay. It is also required for `-lan-discovery` broadcasts. Under bridge networking, traversal still works through STUN/TURN, but publish each forwarded port explicitly with `-p`.
- **Bind address:** always pass `-local-host 0.0.0.0` (or set `local_host` in the mappings). The default `127.0.0.1` is the container's own loopback and is unreachable from the host or the LAN.
- **Device name:** uulink registers the system hostname as the device name. Set `--hostname` (or the `hostname` config field), otherwise the random container ID appears in `-list` and changes on every recreate.
- **Non-root user:** the container runs as UID `10001`. Named volumes inherit the correct ownership automatically; for a bind mount, run `chown 10001:10001 ./data` on the host first, or add `--user "$(id -u):$(id -g)"`. Binding local ports below 1024 additionally needs `--user 0` or `--sysctl net.ipv4.ip_unprivileged_port_start=0`.
- **Zero-argument images:** bake a remote share configuration URL into a custom build for the distribution mode described above:

  ```bash
  docker build --build-arg DEFAULT_CONFIG_URL=https://example.com/room.json -t mc-link .
  ```

## Configuration Reference

`config.json` structure:

```json
{
  "jwt": "User authentication token (auto-populated by -login-qrcode)",
  "client_id": "Unique machine hardware identifier",
  "device_id": "Device identifier on the UU Remote platform",
  "user_id": "User account identifier",
  "hostname": "Optional device name exposed during registration",
  "allow_lan": false,
  "allowed_ports": [22, 8080],
  "sessions": 4,
  "custom_code": "Optional fixed verification code for custom assistance",
  "share_id": "Optional default remote assistance connect ID",
  "share_code": "Optional default remote assistance verification code",
  "mappings": [
    {
      "local_host": "127.0.0.1",
      "local_port": 18080,
      "remote_host": "127.0.0.1",
      "remote_port": 8080
    },
    {
      "local_port": "9000-9005",
      "remote_port": "8000-8005"
    },
    {
      "range": "7000-7002:6000-6002"
    }
  ]
}
```

Field details:

- `jwt`: Authentication token. Recommended to generate automatically via `./uulink -login-qrcode`.
- `client_id`: Unique client identifier (such as system hardware UUID).
- `device_id`: Device identifier registered on UU Remote, visible via `./uulink -list`.
- `user_id`: Registered account user identifier.
- `hostname`: Optional device name exposed to UU Remote. If omitted, the system hostname is used.
- `mappings`: Array of port forwarding rules.
- Mappings are optional. When no mappings are configured, the process accepts only peer-initiated inbound port mappings.
- `local_host`: Local IP address to bind to. Defaults to `127.0.0.1`. Set to `0.0.0.0` to allow other devices on the local network to connect.
- `local_port`: Local port or port range to bind and listen on (e.g. `18080` or `"9000-9005"`).
- `remote_host`: Destination host on the remote end. Typically `127.0.0.1`.
- `remote_port`: Destination port or port range on the remote end (e.g. `8080` or `"8000-8005"`).
- `range`: Optional compact port range mapping specifier (e.g. `"7000-7002:6000-6002"`).
- `allow_lan`: Allow incoming port mappings to target non-loopback LAN/WAN addresses. Defaults to `false` (loopback only). Loopback services are treated as trusted; if a proxy port is exposed, it can still reach other networks, so restrict `allowed_ports` to the service ports you intend to expose.
- `allowed_ports`: Optional array of allowed target ports (e.g. `[22, 8080]`). When the field is omitted, all ports are allowed on permitted hosts. An empty array denies every target port.
- `sessions`: Relay session target, from `1` to `16`. Defaults to `4`; `1` disables pooling. Set `8` on both ends for busier proxy workloads. The `-sessions` flag overrides it. With a single share and a logged-in controller, compatible servers create extra rooms automatically when a relay is detected.
- `share_id`, `share_code`, `custom_code`: Optional defaults for share joins (`-share`, `-custom-connect`). A custom-code server also records its connect ID and code here.
- `unbound_client_id`, `unbound_device_id`: Written by `-unbound-guest-serve` and `-custom-serve` so the accountless device keeps the same connect ID across restarts. Only the single-session server persists them: with a pooled `-unbound-guest-serve` (the default `-sessions 4`) the identity is regenerated on every start, and both the connect IDs and codes change. Use `-custom-serve` for a stable entry point with automatic expansion, or `-sessions 1` for a single session.

Incoming `CONNECT` requests are authorized by the receiving process. Both endpoints use the same mapping schema, and either endpoint may expose local listeners that reach services on the other endpoint, subject to the receiving endpoint's `allow_lan` and `allowed_ports` policy.

## Command-Line Options

| Flag | Description | Default |
| --- | --- | --- |
| `-config <path>` | Path to configuration file | `config.json` |
| `-login` | Interactively select login method (QR code or SMS code) | - |
| `-login-qrcode` | Generate a login QR code and update credentials | - |
| `-login-qrcode-timeout <dur>` | Maximum time to wait for QR-code login confirmation | `5m0s` |
| `-login-mobile <number>` | Mobile phone number for SMS verification code login | - |
| `-login-country-code <code>` | Country code for mobile login (default `+86`) | `+86` |
| `-refresh-login` | Validate current session and refresh if expired | - |
| `-list` | List registered devices and their online status | - |
| `-user-info` | Display current account user info | - |
| `-serve` | Run in server mode waiting for controller connection | - |
| `-device <id>` | Target remote device ID to connect to | config device_id |
| `-local <port/range>` | Local port or port range to listen on (e.g. `8080` or `9000-9010`) | - |
| `-local-host <ip>` | Local address to bind to | `127.0.0.1` |
| `-remote-port <port/range>` | Target port or port range (e.g. `8080` or `9000-9010`) | - |
| `-remote-host <ip>` | Target host on remote end | `127.0.0.1` |
| `-mapping <spec>` | Forwarding rule or range (e.g. `8080:8080` or `9000-9010:8000-8010`) | - |
| `-rule-id <id>` | Target registered rule ID on remote device | - |
| `-transport <mode>` | WebRTC transport policy for controller sessions: `auto` or `relay` | `auto` |
| `-sessions <n>` | Relay session target, `1`–`16` (`1` disables pooling) | `4` |
| `-log-level <level>` | Log level: `debug`, `info`, `warn`, or `error` | `info` |
| `-allow-lan` | Allow incoming connections to target LAN/WAN addresses | off (loopback only) |
| `-allowed-ports <ports>` | Whitelist allowed target ports (e.g. `22,8080,9000-9010`) | all (on loopback) |
| `-unbound-guest-serve` | Register an accountless guest device and print share code | - |
| `-guest-serve` | Run assistance server on current device and print share code | - |
| `-share-auth-mode <mode>` | Guest share authorization mode: `temporary`, `custom`, or `both` | `temporary` |
| `-guest-custom-code <code>` | Custom guest share code for `custom` or `both` modes | - |
| `-share` | Connect to an assistance server by share ID and code | - |
| `-share-guest` | Join remote assistance using an accountless guest identity | - |
| `-share-confirmation` | Join remote assistance by server-side confirmation | - |
| `-share-control-mode` | Query remote assistance control mode and exit | - |
| `-share-id <id>` | Remote assistance connect ID | - |
| `-share-code <code>` | Remote assistance verification code | - |
| `-share-control-id <id>` | Controller control ID for `-share-confirmation` | generated |
| `-custom-serve` | Run assistance server with custom verification code mode | - |
| `-custom-code <code>` | Custom verification code (8-16 alphanumeric characters) | - |
| `-custom-connect <id>` | Connect ID of the assistance server to connect to | - |
| `-config-url <url>` | Fetch remote share configuration and run in client mode | - |
| `-publish-url <url>` | Webhook URL to publish share info on room start | - |
| `-publish-secret <token>` | Optional bearer token for publish webhook | - |
| `-lan-discovery` | Enable Minecraft LAN discovery broadcast for forwarded ports | off |
| `-lan-motd <text>` | Override MOTD text for LAN discovery broadcast | - |

`-transport relay` is a controller-only hard requirement: the controller accepts only TURN relay candidates and fails if no TURN server or relay connection is available. Server modes reject `-transport relay`; a server-side relay requirement is represented by the signaling response, not by a local server flag.

For automatic relay pooling, use `-custom-serve` on the server and join its single share with a logged-in controller. Both ends default to 4 sessions; set `-sessions 8` on both ends for more concurrent downloads, up to 16. The primary share stays stable while additional rooms are created automatically. Older peers and unavailable expansion fall back to the primary session. Each TCP connection stays on one session, so more sessions benefit multiple concurrent connections, not a single download connection.

`-unbound-guest-serve` also supports preparing rooms up front and printing comma-separated share IDs and codes. Pass all pairs to `-share` on the controller. These temporary room identities change after a restart.

The tunnel now retries transient signaling and transport failures with bounded backoff. Pooled relay sessions are monitored independently: a failed session is removed, its affected TCP streams are closed, and the pool requests a replacement while healthy sessions continue serving new streams. An interrupted TCP stream cannot be moved transparently to another transport, so the application must retry that transfer.

## Known Issues

- **The controlling side must be logged in.** A share join performed with an
  ephemeral guest identity — `-share-guest`, or `-custom-connect` / `-config-url`
  on a config without a `jwt` — always fails with
  `code 1002: 查询对象不存在`. This is a server-side restriction rather than a
  missing step in uulink: the API scopes share lookups to logged-in users, and no
  guest-namespace join endpoint exists. Probing confirmed that the guest token
  itself is accepted (omitting it returns `1120`, not `1002`), that
  `/api/v2/room/join/share/by_code` and its v1 twin both answer `1002` for
  guests while every `/api/v1/guest/room/join/...` candidate returns HTTP 404,
  and that the result is identical for temporary-code and custom-code shares and
  unchanged by creating a guest room first. The *served* side can still stay
  accountless, which is what Methods 3, 4, and 5 are for; only the connecting
  side needs an account. uulink now reports this with an explicit message
  instead of the raw API error.

## FAQ

**Q: The client reports that the target device is offline or cannot connect.**

1. Ensure the target machine is actively running `./uulink -serve` (or running the official client).
2. Verify that `-device` matches the target machine device ID exactly (check with `./uulink -list`).
3. Check whether your login session has expired by running `./uulink -refresh-login`.

**Q: What is the expected transfer speed and latency?**

Whenever network conditions allow, uulink negotiates a direct peer-to-peer (P2P) connection. Traffic flows directly between the two endpoints without intermediate server bottlenecks, bound only by your actual upload and download bandwidth. If both sides are behind symmetric NATs that prevent direct traversal, traffic automatically falls back to official relay nodes.

Note that NAT type is not the only factor: the signaling response can mark a room
as relay-only (`server_requires_relay=true`), which is common for share and guest
rooms. In that case every stream goes through a TURN relay even when both peers
are directly reachable, and latency is dominated by the relay path.

**Q: Can other devices on my local network access the forwarded port?**

Yes. By default, local listeners bind to `127.0.0.1` for security. To expose the port across your local network (e.g., for a phone or another computer), set `-local-host 0.0.0.0` on the command line or set `"local_host": "0.0.0.0"` in your `config.json` mapping rule.
