# mac-security-audit

A single-file security audit script for macOS. Run it on any Mac to get an instant overview of your security posture.

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey)
![Shell](https://img.shields.io/badge/shell-bash-green)

## What it checks

| Category | Details |
|----------|---------|
| **Firewall** | Global state, stealth mode |
| **FileVault** | Disk encryption status |
| **SIP** | System Integrity Protection |
| **Gatekeeper** | App verification |
| **Remote Access** | SSH, Screen Sharing, ARD |
| **Listening Ports** | All TCP listeners, flags wildcard bindings |
| **AI Agents** | Ollama, LLaMA, OpenClaw, LM Studio, ComfyUI, and more |
| **LaunchAgents** | Custom user agents (filters out Apple/known vendors) |
| **LaunchDaemons** | Third-party system daemons |
| **Cron Jobs** | User crontab entries |
| **Login Items** | Apps that start on login |
| **Home Directory** | Permission check (should be 700) |
| **SSH** | Key permissions, authorized_keys review |
| **Sensitive Files** | .env, credentials.json, .netrc, etc. |
| **Software Updates** | Pending macOS updates |
| **Power Management** | Sleep/display sleep settings |

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/fullstacksushil/mac-security-audit/main/mac-security-audit.sh | bash
```

Or clone and run:

```bash
git clone https://github.com/fullstacksushil/mac-security-audit.git
cd mac-security-audit
chmod +x mac-security-audit.sh
./mac-security-audit.sh
```

## Full audit (recommended)

Run with `sudo` to unlock firewall and sharing service checks:

```bash
sudo ./mac-security-audit.sh
```

Without `sudo`, the script still runs but skips checks that require root access (firewall state, screen sharing, remote desktop).

## Sample output

```
═══ System Info ═══
[INFO] Hostname: my-mac
[INFO] macOS: 15.3.1 (24D70)
[INFO] Chip: Apple M4
[INFO] User: root (UID 0)

═══ Firewall ═══
[ OK ] Firewall is enabled
[ OK ] Stealth mode is enabled

═══ FileVault (Disk Encryption) ═══
[ OK ] FileVault is ON

═══ System Integrity Protection ═══
[ OK ] SIP is enabled

═══ Listening Ports ═══
[WARN] The following are bound to ALL interfaces (not just localhost):
  rapportd        *:49152

═══ SSH Configuration ═══
[ OK ] .ssh directory is 700
[ OK ] No authorized_keys file

═══ Audit Complete ═══
No critical issues found.
```

## Output legend

| Tag | Meaning |
|-----|---------|
| `[ OK ]` | Check passed |
| `[INFO]` | Informational (review manually) |
| `[WARN]` | Non-critical but worth reviewing |
| `[ALERT]` | Critical issue that should be fixed |

## Requirements

- macOS 12+ (Monterey or later)
- Bash 3.2+ (ships with macOS)
- No dependencies — uses only built-in macOS tools

## License

MIT
