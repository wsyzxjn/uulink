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
      "local_port": 2222,
      "remote_port": 22
    },
    {
      "local_port": 8080,
      "remote_port": 80
    }
  ]
}
```

Start the endpoints without passing port flags:

- Target machine: `./uulink -serve`
- Client machine: `./uulink -device <TARGET_DEVICE_ID>`

All configured ports will be mapped simultaneously.

### Method 3: Temporary Connection via Share Code

Use this method when machines are on different accounts or for temporary access without binding devices.

1. Start the assistance service on the target machine:

```bash
./uulink -guest-serve
```

The terminal will display a `connect_id` and an 8-character `connect_code`.

2. Connect from the client machine using the share credentials:

```bash
./uulink -share -share-id <CONNECT_ID> -share-code <CONNECT_CODE> -local 18080 -remote-port 8080
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
- `allowed_ports`: Optional array of allowed target ports (e.g. `[22, 8080]`). When set, incoming connections to other ports are rejected.

## Command-Line Options

| Flag | Description | Default |
| --- | --- | --- |
| `-config <path>` | Path to configuration file | `config.json` |
| `-login-qrcode` | Generate a login QR code and update credentials | - |
| `-refresh-login` | Validate current session and refresh if expired | - |
| `-list` | List registered devices and their online status | - |
| `-user-info` | Display current account user info | - |
| `-serve` | Run in server mode waiting for controller connection | - |
| `-device <id>` | Target remote device ID to connect to | config device_id |
| `-local <port>` | Local port to listen on | - |
| `-local-host <ip>` | Local address to bind to | `127.0.0.1` |
| `-remote-port <port>` | Target port on remote host | - |
| `-remote-host <ip>` | Target host on remote end | `127.0.0.1` |
| `-force-relay` | Force WebRTC to use TURN relay only | off |
| `-log-level <level>` | Log level: `debug`, `info`, `warn`, or `error` | `info` |
| `-allow-lan` | Allow incoming connections to target LAN/WAN addresses | off (loopback only) |
| `-allowed-ports <ports>` | Whitelist allowed target ports (e.g. `22,8080,9000-9010`) | all (on loopback) |
| `-guest-serve` | Run assistance server and print share code | - |
| `-share` | Enable share code client mode | - |
| `-share-id <id>` | Remote assistance connect ID | - |
| `-share-code <code>` | Remote assistance verification code | - |

## FAQ

**Q: The client reports that the target device is offline or cannot connect.**

1. Ensure the target machine is actively running `./uulink -serve` (or running the official client).
2. Verify that `-device` matches the target machine device ID exactly (check with `./uulink -list`).
3. Check whether your login session has expired by running `./uulink -refresh-login`.

**Q: What is the expected transfer speed and latency?**

Whenever network conditions allow, uulink negotiates a direct peer-to-peer (P2P) connection. Traffic flows directly between the two endpoints without intermediate server bottlenecks, bound only by your actual upload and download bandwidth. If both sides are behind symmetric NATs that prevent direct traversal, traffic automatically falls back to official relay nodes.

**Q: Can other devices on my local network access the forwarded port?**

Yes. By default, local listeners bind to `127.0.0.1` for security. To expose the port across your local network (e.g., for a phone or another computer), set `-local-host 0.0.0.0` on the command line or set `"local_host": "0.0.0.0"` in your `config.json` mapping rule.
