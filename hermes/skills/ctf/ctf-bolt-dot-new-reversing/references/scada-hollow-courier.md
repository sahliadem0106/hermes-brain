# SCADA/ICS Challenge Reference — Hollow Courier / Salt Gate

## Service Layout (154.57.164.72)

| Port | Service | Notes |
|------|---------|-------|
| 30416 | Flask HMI + Git interface | Flask app under `/app/`, git under `/` |
| 31600 | RF-433 MHz keyfob channel | Text protocol, commands: STATUS, TX, JAM ON/OFF, HELP |
| 31604 | HTTP (nginx) | Returns 400 to raw binary; NOT Modbus |

## HMI Credentials

| Username | Password | Role |
|----------|----------|------|
| ashguard | lantern-guard-1701 | watch |
| lysa | crown-ledger-8820 | clerk |
| garran | road-watch-4418 | captain |

## Git Access
URL: `http://htb_developer:HTBDeveloperPassword@<ip>:<port>/git/core_application.git`

## Key Endpoints

| Path | Method | Auth | Purpose |
|------|--------|------|---------|
| /app/ | GET | Public | Ledger with passages |
| /app/gate/present | POST | Public | Present a writ (writ=token) |
| /app/gate/inspect | GET | Public | Inspect writ (writ=param) |
| /app/gate/decree | POST | Internal only | Seal a decree at inner desk |
| /app/watch | GET | Staff | Watch desk dashboard |

## Internal Desk Bypass

The /app/gate/decree endpoint requires internal IP:
```
INTERNAL_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.2/32")
```
Spoof with header: `X-Forwarded-For: 127.0.0.2, <any_ip>`

## RF-433 MHz Keyfob Protocol

Port: 31600 — Text-based command protocol

### Commands
- STATUS — Show current lock state
- TX <hex> — Transmit an RF frame (18 bytes hex-encoded)
- JAM ON / JAM OFF — Control channel jammer
- HELP — Show available commands
- QUIT — Disconnect

### Frame Structure (18 bytes = 36 hex chars)
- Bytes 0-4: Sync pattern = "River" (hex: 5269766572)
- Bytes 5-6: Serial number (2 bytes)
- Bytes 7-8: Rolling counter (2 bytes, increment from last_counter)
- Byte 9: Button code (0x01 = unlock)
- Bytes 10-17: Padding (typically zeros)

### Status Format
STATUS lock=<locked|unlocked> jammer=<on|off> last_counter=<N> flag=<hidden|visible>

The flag=hidden changes to the actual flag when the gate is unlocked.

### Example Frame
52697665720A192531010000000000000000
This frame passed sync detection (got unknown_serial not sync_not_found).
