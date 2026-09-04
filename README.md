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
- Terminal QR code login: Generate a login QR code directly in the terminal to authenticate and write credentials into the configuration file.
- Share code mode: Connect using temporary remote-assistance share codes without requiring devices to belong to the same account.
- Cross-platform: Runs on macOS, Linux, and Windows.

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

Create a configuration file from the template:

```bash
cp config.example.json config.json
```

See [config.example.json](config.example.json) for reference.

### 3. Log In to Your Account

Run the following command to generate a login QR code:

```bash
./uulink -login-qrcode
```

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
DEVICE_ID                NAME             STATUS         PLAT     VERSION
aeawqa5txeafoxl4         MyMac            CONNECTED      4        4.38.0
aeawn7l56uabjgfc         HomePC           CONNECTED      1        2.2.2.2400
```

Note the `DEVICE_ID` of the target machine you want to connect to.

## Usage

### Method 1: Same-Account Device Pairing (Recommended)

Use this method when both machines are registered under the same UU Remote account.

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
./uulink -unbound-guest-serve -local 19081 -remote-port 18090
```

The terminal will display a `connect_id` and an 8-character `connect_code`:

```text
INFO guest share ready: connect_id=266444253 connect_code=6W44YBPL
```

2. Connect from the controlling machine using your credentials and the share code:

```bash
./uulink -share -share-id 266444253 -share-code 6W44YBPL -local 19090 -remote-port 18091
```

Once connected, bidirectional port forwarding between the two endpoints is active immediately.

### Method 4: Fixed Custom Verification Code Mode

Use this method when you want to establish access using a static, memorable password rather than temporary random codes. Neither endpoint requires a logged-in NetEase account; a missing `config.json` is created automatically with a stable client identity.

1. Start the server with a custom code (8-16 alphanumeric characters containing both letters and digits):

```bash
./uulink -custom-serve -custom-code MyPass123 -local 19081 -remote-port 18090
```

The terminal will display the assistance connect ID:

```text
INFO custom assistance ready: connect_id=266444253 custom_code=MyPass123
INFO client command: uulink -custom-connect 266444253 -custom-code MyPass123
```

If `-custom-code` is omitted, `uulink` generates a compliant code and prints it. The server saves its device identity, connect ID, and custom code to `config.json`, so restarting it keeps the same connect ID and code.

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

Use this method for zero-friction distribution to friends or community players. The client fetches share credentials and mapping rules from an HTTP(S) URL (or a local file path) and joins as a guest; no login is required.

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

Field details:

- `jwt`: Authentication token. Recommended to generate automatically via `./uulink -login-qrcode`.
- `client_id`: Unique client identifier (such as system hardware UUID).
- `device_id`: Device identifier registered on UU Remote, visible via `./uulink -list`.
- `user_id`: Registered account user identifier.
- `hostname`: Optional device name exposed to UU Remote. If omitted, the system hostname is used.
- `mappings`: Array of port forwarding rules.
- Mappings are optional. When no mappings are configured, the process accepts only peer-initiated inbound port mappings.
- `local_host`: Local IP address to bind to. Defaults to `127.0.0.1`. Set to `0.0.0.0` to allow other devices on the local network to connect.
- `local_port`: Local port to bind and listen on.
- `remote_host`: Destination host on the remote end. Typically `127.0.0.1`.
- `remote_port`: Destination port on the remote end.
- `allow_lan`: Allow incoming port mappings to target non-loopback LAN/WAN addresses. Defaults to `false` (loopback only). Loopback services are treated as trusted; if a proxy port is exposed, it can still reach other networks, so restrict `allowed_ports` to the service ports you intend to expose.
- `allowed_ports`: Optional array of allowed target ports (e.g. `[22, 8080]`). When the field is omitted, all ports are allowed on permitted hosts. An empty array denies every target port.
- `sessions`: Optional relay session pool size for `-unbound-guest-serve`. Defaults to `4`; set `1` to serve a single session. The `-sessions` flag overrides it.
- `share_id`, `share_code`, `custom_code`: Optional defaults for share joins (`-share`, `-custom-connect`). A custom-code server also records its connect ID and code here.
- `unbound_client_id`, `unbound_device_id`: Written by `-unbound-guest-serve` and `-custom-serve` so the accountless device keeps the same connect ID across restarts.

Incoming `CONNECT` requests are authorized by the receiving process. Both endpoints use the same mapping schema, and either endpoint may expose local listeners that reach services on the other endpoint, subject to the receiving endpoint's `allow_lan` and `allowed_ports` policy.

## Command-Line Options

| Flag | Description | Default |
| --- | --- | --- |
| `-config <path>` | Path to configuration file | `config.json` |
| `-login` | Interactively select login method (QR code or SMS code) | - |
| `-login-qrcode` | Generate a login QR code and update credentials | - |
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
| `-transport <mode>` | WebRTC transport policy for controller sessions: `auto` or `relay` | `auto` |
| `-sessions <n>` | Relay session pool size for `-unbound-guest-serve` (`1` disables pooling) | `4` |
| `-log-level <level>` | Log level: `debug`, `info`, `warn`, or `error` | `info` |
| `-allow-lan` | Allow incoming connections to target LAN/WAN addresses | off (loopback only) |
| `-allowed-ports <ports>` | Whitelist allowed target ports (e.g. `22,8080,9000-9010`) | all (on loopback) |
| `-unbound-guest-serve` | Register an accountless guest device and print share code | - |
| `-guest-serve` | Run assistance server on current device and print share code | - |
| `-share` | Connect to an assistance server by share ID and code | - |
| `-share-id <id>` | Remote assistance connect ID | - |
| `-share-code <code>` | Remote assistance verification code | - |
| `-custom-serve` | Run assistance server with custom verification code mode | - |
| `-custom-code <code>` | Custom verification code (8-16 alphanumeric characters) | - |
| `-custom-connect <id>` | Connect ID of the assistance server to connect to | - |
| `-config-url <url>` | Fetch remote share configuration and run in client mode | - |
| `-publish-url <url>` | Webhook URL to publish share info on room start | - |
| `-publish-secret <token>` | Optional bearer token for publish webhook | - |
| `-lan-discovery` | Enable Minecraft LAN discovery broadcast for forwarded ports | off |
| `-lan-motd <text>` | Override MOTD text for LAN discovery broadcast | - |

`-transport relay` is a controller-only hard requirement: the controller accepts only TURN relay candidates and fails if no TURN server or relay connection is available. Server modes reject `-transport relay`; a server-side relay requirement is represented by the signaling response, not by a local server flag.

Relayed connections are rate limited per TURN allocation. `-unbound-guest-serve` therefore opens one guest room per pooled session (default `4`) and prints a comma-separated `-share-id`/`-share-code` pair. Pass those values to `-share` (or `-share-guest`) on the controller and each TCP stream is pinned to one of the sessions, so the sessions share the load while every stream stays in order. Use `-sessions 1` to run a single session.

## FAQ

**Q: The client reports that the target device is offline or cannot connect.**

1. Ensure the target machine is actively running `./uulink -serve` (or running the official client).
2. Verify that `-device` matches the target machine device ID exactly (check with `./uulink -list`).
3. Check whether your login session has expired by running `./uulink -refresh-login`.

**Q: What is the expected transfer speed and latency?**

Whenever network conditions allow, uulink negotiates a direct peer-to-peer (P2P) connection. Traffic flows directly between the two endpoints without intermediate server bottlenecks, bound only by your actual upload and download bandwidth. If both sides are behind symmetric NATs that prevent direct traversal, traffic automatically falls back to official relay nodes.

**Q: Can other devices on my local network access the forwarded port?**

Yes. By default, local listeners bind to `127.0.0.1` for security. To expose the port across your local network (e.g., for a phone or another computer), set `-local-host 0.0.0.0` on the command line or set `"local_host": "0.0.0.0"` in your `config.json` mapping rule.
