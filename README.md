# mac-security-audit

Security audit and hardening script for macOS machines running AI agents — OpenClaw, Ollama, Open WebUI, LM Studio, and more.

Built for Mac Minis and other Macs used as always-on AI workstations. One command to find what's exposed, what's misconfigured, and what needs locking down.

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey)
![Shell](https://img.shields.io/badge/shell-bash-green)

## Why this exists

Mac Minis are becoming the go-to for local AI — Ollama, OpenClaw, Open WebUI, LM Studio. But most setups skip security basics:

- Ollama bound to `0.0.0.0` (your models are accessible to the whole network)
- OpenClaw running with weak auth tokens and KeepAlive daemons
- Docker containers exposing ports on all interfaces
- Tailscale Funnel accidentally publishing local services to the internet
- Orphaned agent configs with API keys and secrets sitting on disk
- Firewall off, FileVault off, sleep disabled with no auto-restart

This script finds all of that in seconds.

## Quick start

**Audit only** (safe, read-only):
```bash
curl -fsSL https://raw.githubusercontent.com/fullstacksushil/mac-security-audit/main/mac-security-audit.sh | bash
```

**Full audit** (includes firewall and sharing checks):
```bash
curl -fsSL https://raw.githubusercontent.com/fullstacksushil/mac-security-audit/main/mac-security-audit.sh | sudo bash
```

**Audit + auto-fix** (fixes what it can):
```bash
curl -fsSL https://raw.githubusercontent.com/fullstacksushil/mac-security-audit/main/mac-security-audit.sh | sudo bash -s -- --fix
```

Or clone and run:
```bash
git clone https://github.com/fullstacksushil/mac-security-audit.git
cd mac-security-audit
chmod +x mac-security-audit.sh
sudo ./mac-security-audit.sh --fix
```

## What it checks

### macOS Security
| Check | Details | Auto-fix |
|-------|---------|----------|
| Firewall | Global state + stealth mode | Yes |
| FileVault | Disk encryption | Manual |
| SIP | System Integrity Protection | Manual |
| Gatekeeper | App verification | Yes |
| Remote access | SSH, Screen Sharing, ARD | Yes (SSH) |
| Home directory | Should be chmod 700 | Yes |
| SSH keys | Permissions on private keys | Yes |
| Software updates | Pending macOS updates | Manual |

### AI Agent Security
| Check | Details | Auto-fix |
|-------|---------|----------|
| OpenClaw gateway | Running status, PID, memory | - |
| OpenClaw auth | Token strength (flags weak tokens) | Manual |
| OpenClaw binding | Loopback vs all-interfaces | Manual |
| OpenClaw plugins | Unvetted plugin detection | Manual |
| OpenClaw LaunchAgent | KeepAlive, auto-restart config | Manual |
| Orphaned agents | Detects leftover secrets from unused agents | Manual |
| Ollama binding | `OLLAMA_HOST` in shell config + runtime | Yes |
| Docker containers | Ports exposed on 0.0.0.0 | Manual |
| Docker daemons | Orphaned LaunchDaemons | Yes |
| All AI processes | Ollama, LLaMA, LM Studio, ComfyUI, etc. | - |

### Network & Services
| Check | Details | Auto-fix |
|-------|---------|----------|
| Listening ports | All TCP listeners with wildcard warnings | - |
| Tailscale | Serve/Funnel exposure detection | Manual |
| LaunchAgents | Custom user agents (filters Apple/vendors) | - |
| LaunchDaemons | Third-party system daemons | - |
| Cron jobs | User crontab entries | - |
| Login items | Apps that start on login | - |
| Sensitive files | .env, credentials.json, .netrc, etc. | - |

### Server Configuration
| Check | Details | Auto-fix |
|-------|---------|----------|
| Sleep settings | Reports if sleep is off (expected for servers) | - |
| Auto-restart | Restart on power failure | Yes |
| Power management | Display sleep, hibernate settings | - |

## Sample output

```
  ┌─────────────────────────────────────────┐
  │       mac-security-audit v1.1.0          │
  │   Security audit for macOS AI stations   │
  └─────────────────────────────────────────┘

  Mode: AUDIT + FIX

═══ Firewall ═══
[ OK ] Firewall is enabled
[ OK ] Stealth mode is enabled

═══ AI Agent Services ═══
[INFO] OpenClaw gateway is RUNNING (PID 1401, 1.0% RAM)
[WARN] OpenClaw LaunchAgent installed
[ALERT] OpenClaw gateway token is weak (6 chars) — use a strong secret

═══ Ollama ═══
[ OK ] Ollama is running
[ALERT] Ollama bound to 0.0.0.0 in /Users/you/.zshrc — exposes API to network
[FIXED] Changed OLLAMA_HOST to 127.0.0.1 in /Users/you/.zshrc

═══ Audit Complete ═══
  Found 2 critical issue(s) that should be addressed.
  Auto-fixed 1 issue(s).
```

## Output legend

| Tag | Meaning |
|-----|---------|
| `[ OK ]` | Check passed |
| `[INFO]` | Informational — review manually |
| `[WARN]` | Non-critical but worth reviewing |
| `[ALERT]` | Critical issue — should be fixed |
| `[FIXED]` | Issue auto-fixed (--fix mode) |

## Requirements

- macOS 12+ (Monterey or later)
- Bash 3.2+ (ships with macOS)
- No dependencies — uses only built-in macOS tools

## Contributing

Found something else that should be checked? Open an issue or PR. Especially interested in:

- Additional AI agent frameworks to detect
- macOS hardening checks specific to headless/server use
- Homebrew formula for easier installation

## License

MIT
