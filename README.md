# uulink

uulink is a lightweight TCP port forwarding tool built on the NetEase UU Remote network. It establishes stable point-to-point (P2P) TCP tunnels between devices across private networks without requiring the official GUI client on target machines.

## Use Cases

- Remote administration and development: Direct access to SSH, Remote Desktop (Windows RDP / VNC), or VS Code Remote across NATs and firewalls.
- Private network service access: Connect to private NAS web dashboards, databases, internal APIs, or file shares.
- Game server hosting: Share locally hosted game servers (such as Minecraft or Palworld) with friends without public IP addresses or router port forwarding.
- Headless server deployment: Minimal CPU and memory footprint, suitable for long-running services on headless Linux servers, mini PCs, and workstations.

## Key Features

- Headless CLI: Single self-contained binary with `git`-style subcommands (`uulink serve`, `uulink connect`, `uulink share join`, ...), no desktop environment or graphical interface required.
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
./uulink login
```

(`./uulink login -mobile <number>` logs in with an SMS code instead, and
`./uulink login -interactive` asks which method to use.)

On a config that has never been used, uulink registers a device identity with UU
Remote first and stores it, because the login handshake has to identify this
machine. That happens automatically and only once.

The terminal will display a login QR code URL. Open or scan this link on your mobile client to authorize the login. The credentials will be saved directly to `config.json`.

If credentials expire later, refresh them with:

```bash
./uulink refresh-login
```

### 4. List Registered Devices

List all devices registered under your account:

```bash
./uulink list
```

Example output:

```text
DEVICE_ID                NAME             STATUS         PLAT     CLIENT_ID    VERSION
--------                 ----             ------         ----     ---------    -------
aeaexampleaaaa01         MyMac            CONNECTED      4                     4.38.0
aeaexampleaaaa02         HomePC           CONNECTED      1                     2.2.2.2400
```

Note the `DEVICE_ID` of the target machine you want to connect to. The
`CLIENT_ID` column is normally blank because the device listing API does not
return that field.

## Usage

### Method 1: Same-Account Device Pairing (Recommended)

Use this method when both machines are registered under the same UU Remote
account. Both endpoints must be logged in; `serve` on a config without
credentials fails with `code 1001: 无效的请求参数`.

1. Start the server on the target (controlled) machine:

```bash
./uulink serve
```

2. Connect from the client (controller) machine and map a port:

For example, to map remote Windows Remote Desktop (port 3389) to local port 13389:

```bash
./uulink connect -device <TARGET_DEVICE_ID> -local 13389 -remote-port 3389
```

Once connected, point your RDP client to `127.0.0.1:13389` to reach the remote desktop.

Similarly, to forward an SSH service:

```bash
./uulink connect -device <TARGET_DEVICE_ID> -local 2222 -remote-port 22
```

You can also forward consecutive port ranges or use the compact `-mapping` syntax:

```bash
# Map a port range 1-to-1 (e.g. 6 ports: 9000->8000, 9001->8001, ..., 9005->8005):
./uulink connect -device <TARGET_DEVICE_ID> -local 9000-9005 -remote-port 8000-8005

# Or with compact mapping flag:
./uulink connect -device <TARGET_DEVICE_ID> -mapping 9000-9005:8000-8005
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

- Target machine: `./uulink serve`
- Client machine: `./uulink connect -device <TARGET_DEVICE_ID>`

All configured ports will be mapped simultaneously.

### Method 3: Temporary Connection via Share Code (Guest Mode)

Use this method when machines belong to different accounts or for temporary access without binding the target device to your account. The target machine does not need to be logged in.

1. Start the assistance service on the target machine:

```bash
# Start an accountless share server (no login required on this machine)
./uulink share serve -local 19081 -remote-port 18090
```

By default the terminal displays one `connect_id` and an 8-character
`connect_code`. Auto mode starts with that one stable session and expands the
relay pool in band only when needed:

```text
INFO guest share ready: connect_id=266444253 connect_code=6W44YBPL
```

To force a fixed pool up front, pass `-sessions` with a value greater than `1`.
The pooled server opens one room per session and prints the whole set on a
single line, for direct use as flag values:

```text
INFO multi-session guest shares ready (4 sessions): uulink share join -id 266444253,266444254,... -code 6W44YBPL,7X55ZCQM,...
```

2. Connect from the controlling machine using your credentials and the share code:

```bash
./uulink share join -id 266444253 -code 6W44YBPL -local 19090 -remote-port 18091
```

Once connected, bidirectional port forwarding between the two endpoints is active immediately.

The controller must be logged in. `share join -guest`, which joins with an
ephemeral guest identity so that neither side needs an account, is rejected by
the API — see [Known Issues](#known-issues).

### Method 4: Fixed Custom Verification Code Mode

Use this method when you want to establish access using a static, memorable
password rather than temporary random codes. The server side needs no account: a
missing `config.json` is created automatically with a stable client identity.
The connecting side, however, must be logged in: `share join` falls back to an
ephemeral guest identity when the config has no `jwt`, and the API rejects
guest identities on share joins (see [Known Issues](#known-issues)).

1. Start the server with a custom code (8-16 alphanumeric characters containing both letters and digits):

```bash
./uulink share serve -custom-code MyPass123 -local 19081 -remote-port 18090
```

The terminal will display the assistance connect ID:

```text
INFO custom assistance ready: connect_id=266444253 custom_code=MyPass123
INFO client command: uulink share join -id 266444253 -code MyPass123
```

With `share serve -custom` and no `-custom-code`, `uulink` generates a compliant code and prints it. The server saves its device identity, connect ID, and custom code to `config.json`, so restarting it keeps the same connect ID and code. The primary identity stays persistent even when extra relay sessions are created automatically. A pooled `share serve -sessions N` uses temporary identities instead.

2. Connect from the client using the connect ID and custom code:

```bash
./uulink share join -id 266444253 -code MyPass123 -local 19090 -remote-port 18091
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
./uulink share serve -publish-url "https://example.com/sync" -publish-secret "mysecret" -mapping 25565:25565
```

2. Connect from the client using the configuration URL:

```bash
./uulink connect -config-url https://example.com/room.json
```

Or build a dedicated zero-argument client binary with the URL embedded via ldflags:

```bash
go build -ldflags="-X main.DefaultConfigURL=https://example.com/room.json" -o mc-link ./cmd/uulink
```

Users can simply run `./mc-link` without passing any arguments (it behaves like `mc-link connect -config-url <URL>`); a `config.json` with a random client identity is created next to the binary on first start.

## Docker

Multi-architecture images (`linux/amd64`, `linux/arm64`) are built and published by CI to this repository's GitHub Container Registry for every `v*` release:

```bash
docker pull ghcr.io/wsyzxjn/uulink:latest
```

Available tags: `latest`, the semantic versions of each release (`0.1.7`, `0.1`, `0`), and `sha-<commit>` for the commit a release was built from. Images are not published for ordinary pushes to `main`; build from source (`docker compose up --build`, or `docker build .`) to run unreleased changes.

### Run

The image sets `WORKDIR /data`, so the default `-config` path resolves to `/data/config.json`. Mount a volume there to persist credentials and the accountless device identity across restarts:

```bash
docker volume create uulink-data

# Log in once (interactive terminal required for the QR code)
docker run --rm -it --network host -v uulink-data:/data ghcr.io/wsyzxjn/uulink:latest login

# Then run the forwarder
docker run -d --name uulink --restart unless-stopped \
  --network host --hostname uulink-docker \
  -v uulink-data:/data \
  ghcr.io/wsyzxjn/uulink:latest connect -device TARGET_DEVICE_ID -local-host 0.0.0.0 -mapping 25565:25565
```

Replace `TARGET_DEVICE_ID` with the ID of a remote device running `uulink serve`. Use `uulink list` to find device IDs.

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
- **Device name:** uulink registers the system hostname as the device name. Set `--hostname` (or the `hostname` config field), otherwise the random container ID appears in `uulink list` and changes on every recreate.
- **Non-root user:** the container runs as UID `10001`. Named volumes inherit the correct ownership automatically; for a bind mount, run `chown 10001:10001 ./data` on the host first, or add `--user "$(id -u):$(id -g)"`. Binding local ports below 1024 additionally needs `--user 0` or `--sysctl net.ipv4.ip_unprivileged_port_start=0`.
- **Zero-argument images:** bake a remote share configuration URL into a custom build for the distribution mode described above:

  ```bash
  docker build --build-arg DEFAULT_CONFIG_URL=https://example.com/room.json -t mc-link .
  ```

## Configuration Reference

`config.json` structure:

```json
{
  "jwt": "User authentication token (auto-populated by uulink login)",
  "client_id": "Unique machine hardware identifier",
  "device_id": "Device identifier on the UU Remote platform",
  "user_id": "User account identifier",
  "hostname": "Optional device name exposed during registration",
  "allow_lan": false,
  "allowed_ports": [22, 8080],
  "session_mode": "auto",
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

- `jwt`: Authentication token. Recommended to generate automatically via `./uulink login`.
- `client_id`: Unique client identifier (such as system hardware UUID).
- `device_id`: Device identifier registered on UU Remote, visible via `./uulink list`.
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
- `session_mode`: `auto` or `manual`. Defaults to `auto`. Auto starts with one primary session and creates a bounded number of additional relay sessions in band when a relay is detected.
- `sessions`: Relay session target, from `1` to `16`. When `session_mode` is `auto`, it is the pool cap and defaults to `4`. When `session_mode` is `manual`, it is the fixed target. The `-sessions` flag overrides both fields; `-sessions auto` uses the default cap, while a numeric value requests a fixed manual target.
- `share_id`, `share_code`, `custom_code`: Optional defaults for `share join`. A custom-code server also records its connect ID and code here.
- `unbound_client_id`, `unbound_device_id`: Written by `share serve` so the accountless device keeps the same connect ID across restarts. Only the single-session server persists them: with a pooled `share serve -sessions N` (N greater than `1`) the identity is regenerated on every start, and both the connect IDs and codes change. Use `share serve -custom` for a stable entry point with automatic expansion.

uulink rewrites `config.json` after a login or device registration. Keys it does not recognize are preserved, and port ranges are written back in the same `"local_port": "9000-9005"` form they were read in.

Incoming `CONNECT` requests are authorized by the receiving process. Both endpoints use the same mapping schema, and either endpoint may expose local listeners that reach services on the other endpoint, subject to the receiving endpoint's `allow_lan` and `allowed_ports` policy.

## Command Reference

```text
uulink <command> [flags]
```

| Command | Purpose | Needs login |
| --- | --- | --- |
| `login` | Log in (QR-code link by default; `-mobile <number>` for SMS; `-interactive` to choose) and save the credentials | creates it |
| `refresh-login` | Validate the saved login and re-run the QR-code login only if it expired | - |
| `list` | List the account's devices and their online status | yes |
| `whoami` | Show the logged-in user | yes |
| `serve` | Expose this account's device to `connect` controllers | yes |
| `connect` | Connect to a device of the same account (`-device`) or via a remote share configuration (`-config-url`) | yes |
| `share serve` | Serve this machine through a connect ID and code (`-custom` / `-custom-code` for a fixed code; `-account` to reuse the config's device identity) | no |
| `share join` | Join a served share by `-id` and `-code` | yes |
| `share info` | Query the control mode of a share | yes |
| `version` | Print the version, commit, build date, and platform | - |

`uulink help <command>` prints the flags of a command; `uulink <command> -help-debug` also lists the same-host debugging flags (`-room-file`, `-allow-self`, `-control-device-id`, `-control-id`, `-cap`). Flags may be written with one or two dashes.

Global flags, accepted before the command and by every command:

| Flag | Description | Default |
| --- | --- | --- |
| `-config <path>` | Path to the configuration file | `config.json` |
| `-log-level <level>` | Log level: `debug`, `info`, `warn`, or `error` | `info` |

Mapping flags, shared by `serve`, `connect`, `share serve`, and `share join`:

| Flag | Description | Default |
| --- | --- | --- |
| `-local <port/range>` | Local port or port range to listen on (e.g. `8080` or `9000-9010`) | - |
| `-local-host <ip>` | Local address to bind to | `127.0.0.1` |
| `-remote-port <port/range>` | Target port or port range (e.g. `8080` or `9000-9010`) | - |
| `-remote-host <ip>` | Target host on remote end | `127.0.0.1` |
| `-mapping <spec>` | Forwarding rule or range (e.g. `8080:8080` or `9000-9010:8000-8010`) | - |
| `-rule-id <id>` | Target registered rule ID on remote device | - |
| `-allow-lan` | Allow incoming connections to target LAN/WAN addresses | off (loopback only) |
| `-allowed-ports <ports>` | Whitelist allowed target ports (e.g. `22,8080,9000-9010`) | all (on loopback) |
| `-sessions <mode>` | Relay session mode: `auto` or a fixed target `1`-`16` | `auto` |

Controller flags, shared by `connect` and `share join`:

| Flag | Description | Default |
| --- | --- | --- |
| `-transport <mode>` | WebRTC transport policy: `auto` or `relay` | `auto` |
| `-p2p-timeout <dur>` | How long to wait for a direct P2P connection before retrying with a TURN relay; `0` disables the fallback | `12s` |
| `-lan-discovery` | Enable Minecraft LAN discovery broadcast for the first forwarded port | off |
| `-lan-motd <text>` | Override MOTD text for LAN discovery broadcast | - |

Command-specific flags:

| Command | Flag | Description | Default |
| --- | --- | --- | --- |
| `login` | `-mobile <number>` | Log in with an SMS verification code sent to this number | - |
| `login` | `-country-code <code>` | Country code for the mobile number | `+86` |
| `login` | `-interactive` | Choose the login method at a prompt | - |
| `login`, `refresh-login` | `-timeout <dur>` | Maximum time to wait for QR-code login confirmation | `5m0s` |
| `connect` | `-device <id>` | Device ID of a same-account device running `uulink serve` | - |
| `connect` | `-config-url <url>` | URL or file path of a remote share configuration | build default |
| `share serve` | `-custom` | Use a fixed custom verification code (generated when `-custom-code` is empty) | - |
| `share serve` | `-custom-code <code>` | Custom verification code (8-16 letters and digits); implies `-custom` | - |
| `share serve` | `-auth-mode <mode>` | Share authorization mode: `temporary`, `custom`, or `both` | `temporary` |
| `share serve` | `-account` | Reuse the device identity already in the config (from `login` or an earlier `share serve`) instead of registering a new accountless device | - |
| `share serve` | `-publish-url <url>` | Webhook URL that receives the share configuration on room start | - |
| `share serve` | `-publish-secret <token>` | Bearer token sent with `-publish-url` requests | - |
| `share join` | `-id <id>` | Connect ID (comma-separated IDs join one pooled session per share) | config `share_id` |
| `share join` | `-code <code>` | Verification code, temporary or custom (comma-separated for pooled joins) | config `share_code` / `custom_code` |
| `share join` | `-guest` | Join with an ephemeral guest identity (rejected by the API, see Known Issues) | - |
| `share join` | `-confirm` | Join by server-side confirmation instead of a code | - |
| `share join` | `-control-id <id>` | Controller control ID for `-confirm` | generated |
| `share info` | `-id <id>` | Connect ID to query | - |

The protocol experiments from the reverse-engineering phase (`-pck-sweep`, `-mixkcp`) are not part of a normal build; compile with `go build -tags experiments ./cmd/uulink` to get them on the controller commands.

`-transport relay` is a controller-only hard requirement: the controller accepts only TURN relay candidates and fails if no TURN server or relay connection is available. The serving commands have no `-transport` flag; a server-side relay requirement is represented by the signaling response, not by a local server flag.

For automatic relay pooling, use `share serve -custom` on the server and join its single share with a logged-in controller. Auto mode is the default and uses a default cap of `4` sessions; set `-sessions 8` on both ends for a larger cap, up to 16. The primary share stays stable while additional rooms are created automatically. Older peers and unavailable expansion fall back to the primary session. Each TCP connection stays on one session, so more sessions benefit multiple concurrent connections, not a single download connection.

`share serve -sessions N` also supports preparing rooms up front and printing comma-separated share IDs and codes. Pass all pairs to `share join` on the controller. These temporary room identities change after a restart.

Every long-running command (`serve`, `share serve`, `connect`, `share join`, including pooled joins) retries transient signaling and transport failures with bounded backoff. Errors that a retry cannot fix end the process instead, so a supervisor such as systemd or Docker's restart policy sees the failure: invalid flags or mappings exit with status `2`, and runtime failures such as an expired login (`1120`), bad parameters (`1001`), or a wrong share code exit with status `1`. Press Ctrl-C once to shut down cleanly; a second Ctrl-C terminates immediately if a pending network call is still blocking.

Pooled relay sessions are monitored independently: a failed session is removed, its affected TCP streams are closed, and the pool requests a replacement while healthy sessions continue serving new streams. An interrupted TCP stream cannot be moved transparently to another transport, so the application must retry that transfer.

## Known Issues

- **The controlling side must be logged in.** A share join performed with an
  ephemeral guest identity — `share join -guest`, or `share join` / `connect
  -config-url` on a config without a `jwt` — always fails with
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

1. Ensure the target machine is actively running `./uulink serve` (or running the official client).
2. Verify that `-device` matches the target machine device ID exactly (check with `./uulink list`).
3. Check whether your login session has expired by running `./uulink refresh-login`.

**Q: What is the expected transfer speed and latency?**

Whenever network conditions allow, uulink negotiates a direct peer-to-peer (P2P) connection. Traffic flows directly between the two endpoints without intermediate server bottlenecks, bound only by your actual upload and download bandwidth. If both sides are behind symmetric NATs that prevent direct traversal, traffic automatically falls back to official relay nodes.

Note that NAT type is not the only factor: the signaling response can mark a room
as relay-only (`server_requires_relay=true`), which is common for share and guest
rooms. In that case every stream goes through a TURN relay even when both peers
are directly reachable, and latency is dominated by the relay path.

**Q: Can other devices on my local network access the forwarded port?**

Yes. By default, local listeners bind to `127.0.0.1` for security. To expose the port across your local network (e.g., for a phone or another computer), set `-local-host 0.0.0.0` on the command line or set `"local_host": "0.0.0.0"` in your `config.json` mapping rule.

## Disclaimer

This project is an independent open-source tool and is not affiliated with, sponsored by, or endorsed by NetEase, Inc. or NetEase UU Remote. All product names, trademarks, and registered trademarks belong to their respective owners.

- Educational and research purpose: This project is developed and shared solely for technical research, learning, and network interoperability testing. Do not use this tool for unauthorized access, commercial purposes, or unlawful activities.
- No warranty: This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.
- Limitation of liability: In no event shall the authors or contributors be liable for any direct, indirect, incidental, special, or consequential damages, service disruptions, account restrictions, or data loss arising from the use of or inability to use this software.
- Compliance: Users are solely responsible for ensuring that their use of this software complies with applicable local laws, regulations, and third-party terms of service.
