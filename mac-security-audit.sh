#!/bin/bash
# mac-security-audit.sh — Security audit & hardening for macOS AI workstations
# Designed for Mac Minis running OpenClaw, Ollama, and other AI agents
#
# Usage:
#   ./mac-security-audit.sh          # Audit only
#   ./mac-security-audit.sh --fix    # Audit + fix what can be auto-fixed
#   sudo ./mac-security-audit.sh     # Full audit (includes firewall, sharing)
#   sudo ./mac-security-audit.sh --fix  # Full audit + fix everything

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

FIX_MODE=false
[[ "${1:-}" == "--fix" ]] && FIX_MODE=true

warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $1"; }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
alert() { echo -e "${RED}[ALERT]${NC} $1"; }
fixed() { echo -e "${GREEN}[FIXED]${NC} $1"; }
header(){ echo -e "\n${BOLD}═══ $1 ═══${NC}"; }

ISSUES=0
FIXED=0
issue() { alert "$1"; ((ISSUES++)); }

banner() {
    echo -e "${BOLD}"
    echo "  ┌─────────────────────────────────────────┐"
    echo "  │       mac-security-audit v1.1.0          │"
    echo "  │   Security audit for macOS AI stations   │"
    echo "  └─────────────────────────────────────────┘"
    echo -e "${NC}"
    if $FIX_MODE; then
        echo -e "  ${GREEN}Mode: AUDIT + FIX${NC}"
    else
        echo -e "  ${CYAN}Mode: AUDIT ONLY${NC} ${DIM}(use --fix to auto-fix issues)${NC}"
    fi
    echo ""
}

banner

# ─── System Info ───
header "System Info"
info "Hostname: $(hostname)"
info "macOS: $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
info "Chip: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'unknown')"
info "User: $(whoami) (UID $(id -u))"
info "Date: $(date)"

# ─── Firewall ───
header "Firewall"
if [[ $EUID -eq 0 ]]; then
    FW_STATE=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
    if echo "$FW_STATE" | grep -q "enabled"; then
        ok "Firewall is enabled"
    else
        issue "Firewall is DISABLED"
        if $FIX_MODE; then
            /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on >/dev/null 2>&1
            fixed "Firewall enabled"
            ((FIXED++))
        else
            echo -e "  ${DIM}Fix: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on${NC}"
        fi
    fi

    STEALTH=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)
    if echo "$STEALTH" | grep -q "enabled"; then
        ok "Stealth mode is enabled"
    else
        warn "Stealth mode is disabled (machine responds to pings)"
        if $FIX_MODE; then
            /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on >/dev/null 2>&1
            fixed "Stealth mode enabled"
            ((FIXED++))
        else
            echo -e "  ${DIM}Fix: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on${NC}"
        fi
    fi
else
    warn "Run with sudo to check/fix firewall status"
fi

# ─── FileVault ───
header "FileVault (Disk Encryption)"
FV_STATUS=$(fdesetup status 2>/dev/null || echo "unknown")
if echo "$FV_STATUS" | grep -q "On"; then
    ok "FileVault is ON"
else
    issue "FileVault is OFF — your disk is not encrypted"
    echo -e "  ${DIM}Fix: System Settings > Privacy & Security > FileVault > Turn On${NC}"
fi

# ─── SIP (System Integrity Protection) ───
header "System Integrity Protection"
SIP_STATUS=$(csrutil status 2>/dev/null || echo "unknown")
if echo "$SIP_STATUS" | grep -q "enabled"; then
    ok "SIP is enabled"
else
    issue "SIP is DISABLED — re-enable from Recovery Mode: csrutil enable"
fi

# ─── Gatekeeper ───
header "Gatekeeper"
GK_STATUS=$(spctl --status 2>/dev/null || echo "unknown")
if echo "$GK_STATUS" | grep -q "enabled"; then
    ok "Gatekeeper is enabled"
else
    issue "Gatekeeper is DISABLED"
    if $FIX_MODE && [[ $EUID -eq 0 ]]; then
        spctl --master-enable 2>/dev/null
        fixed "Gatekeeper enabled"
        ((FIXED++))
    else
        echo -e "  ${DIM}Fix: sudo spctl --master-enable${NC}"
    fi
fi

# ─── Remote Access ───
header "Remote Access Services"
check_sharing() {
    local service="$1"
    local label="$2"
    if [[ $EUID -eq 0 ]]; then
        if launchctl list 2>/dev/null | grep -q "$service"; then
            issue "$label is ENABLED"
        else
            ok "$label is disabled"
        fi
    fi
}

if systemsetup -getremotelogin 2>/dev/null | grep -qi "on"; then
    issue "Remote Login (SSH) is ENABLED"
    if $FIX_MODE && [[ $EUID -eq 0 ]]; then
        systemsetup -setremotelogin off 2>/dev/null
        fixed "Remote Login (SSH) disabled"
        ((FIXED++))
    else
        echo -e "  ${DIM}Fix: sudo systemsetup -setremotelogin off${NC}"
    fi
else
    ok "Remote Login (SSH) is disabled"
fi

if [[ $EUID -eq 0 ]]; then
    check_sharing "com.apple.screensharing" "Screen Sharing"
    check_sharing "com.apple.RemoteDesktop" "Remote Desktop (ARD)"
else
    warn "Run with sudo to check sharing services"
fi

# ─── OpenClaw / AI Agent Services ───
header "AI Agent Services (OpenClaw, ZeroClaw, etc.)"

# Check for OpenClaw
OPENCLAW_PLIST="$HOME/Library/LaunchAgents/ai.openclaw.gateway.plist"
OPENCLAW_RUNNING=false
OPENCLAW_CONFIG="$HOME/.openclaw/openclaw.json"

if ps aux | grep -i "openclaw" | grep -v grep >/dev/null 2>&1; then
    OPENCLAW_RUNNING=true
    OPENCLAW_PID=$(ps aux | grep -i "openclaw-gateway" | grep -v grep | awk '{print $2}' | head -1)
    OPENCLAW_MEM=$(ps aux | grep -i "openclaw-gateway" | grep -v grep | awk '{print $4}' | head -1)
    info "OpenClaw gateway is RUNNING (PID $OPENCLAW_PID, ${OPENCLAW_MEM}% RAM)"
fi

if [[ -f "$OPENCLAW_PLIST" ]]; then
    warn "OpenClaw LaunchAgent installed: $OPENCLAW_PLIST"

    # Check KeepAlive
    if defaults read "$OPENCLAW_PLIST" KeepAlive 2>/dev/null | grep -q "1"; then
        warn "  KeepAlive=true (auto-restarts if killed)"
    fi

    # Check binding
    if grep -q "0.0.0.0" "$OPENCLAW_PLIST" 2>/dev/null; then
        issue "  OpenClaw gateway bound to 0.0.0.0 (all interfaces) — should be loopback"
    fi
fi

# Check OpenClaw config for weak auth
if [[ -f "$OPENCLAW_CONFIG" ]]; then
    if grep -q '"token"' "$OPENCLAW_CONFIG" 2>/dev/null; then
        TOKEN=$(grep '"token"' "$OPENCLAW_CONFIG" | head -1 | sed 's/.*: *"\([^"]*\)".*/\1/')
        TOKEN_LEN=${#TOKEN}
        if [[ $TOKEN_LEN -lt 16 ]]; then
            issue "OpenClaw gateway token is weak ($TOKEN_LEN chars) — use a strong secret"
            echo -e "  ${DIM}Fix: Change token in $OPENCLAW_CONFIG to a random 32+ char string${NC}"
        else
            ok "OpenClaw gateway token length is adequate ($TOKEN_LEN chars)"
        fi
    fi

    # Check binding mode
    if grep -q '"bind"' "$OPENCLAW_CONFIG" 2>/dev/null; then
        BIND_MODE=$(grep '"bind"' "$OPENCLAW_CONFIG" | head -1 | sed 's/.*: *"\([^"]*\)".*/\1/')
        if [[ "$BIND_MODE" == "loopback" ]]; then
            ok "OpenClaw gateway bound to loopback only"
        else
            issue "OpenClaw gateway bind mode: $BIND_MODE — should be 'loopback'"
        fi
    fi

    # Check for unvetted plugins
    if grep -q '"enabled": true' "$OPENCLAW_CONFIG" 2>/dev/null; then
        PLUGIN_COUNT=$(grep -c '"enabled": true' "$OPENCLAW_CONFIG" 2>/dev/null || echo "0")
        if [[ $PLUGIN_COUNT -gt 0 ]]; then
            warn "OpenClaw has $PLUGIN_COUNT enabled plugin(s) — verify plugins.allow is set"
        fi
    fi
fi

# Check for ZeroClaw remnants
ZEROCLAW_CONFIG="$HOME/.zeroclaw/config.toml"
if [[ -f "$ZEROCLAW_CONFIG" ]]; then
    warn "ZeroClaw config found at $ZEROCLAW_CONFIG"
    if grep -qiE "api_key|secret|token|password" "$ZEROCLAW_CONFIG" 2>/dev/null; then
        issue "ZeroClaw config contains secrets — securely delete if not in use"
        echo -e "  ${DIM}Fix: rm -rf ~/.zeroclaw/ (if fully migrated)${NC}"
    fi
fi
if [[ -f "$HOME/.zeroclaw/otp-secret" ]]; then
    issue "ZeroClaw OTP secret on disk: ~/.zeroclaw/otp-secret"
fi
if [[ -f "$HOME/.zeroclaw/.secret_key" ]]; then
    issue "ZeroClaw secret key on disk: ~/.zeroclaw/.secret_key"
fi

# ─── Ollama Configuration ───
header "Ollama"
OLLAMA_RUNNING=false
if ps aux | grep -i "[o]llama" | grep -v grep >/dev/null 2>&1; then
    OLLAMA_RUNNING=true
    ok "Ollama is running"
fi

# Check OLLAMA_HOST in shell config
for rcfile in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
    if [[ -f "$rcfile" ]]; then
        OLLAMA_HOST_LINE=$(grep 'OLLAMA_HOST' "$rcfile" 2>/dev/null | grep -v '^#' || true)
        if [[ -n "$OLLAMA_HOST_LINE" ]]; then
            if echo "$OLLAMA_HOST_LINE" | grep -q "0.0.0.0"; then
                issue "Ollama bound to 0.0.0.0 in $rcfile — exposes API to network"
                if $FIX_MODE; then
                    sed -i '' 's/OLLAMA_HOST="0\.0\.0\.0/OLLAMA_HOST="127.0.0.1/' "$rcfile" 2>/dev/null && {
                        fixed "Changed OLLAMA_HOST to 127.0.0.1 in $rcfile"
                        ((FIXED++))
                    }
                else
                    echo -e "  ${DIM}Fix: Change to OLLAMA_HOST=\"127.0.0.1:11434\" in $rcfile${NC}"
                fi
            elif echo "$OLLAMA_HOST_LINE" | grep -q "127.0.0.1\|localhost"; then
                ok "Ollama bound to localhost in $rcfile"
            fi
        fi
    fi
done

# Check actual binding if running
if $OLLAMA_RUNNING; then
    OLLAMA_LISTEN=$(lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | grep ollama || true)
    if echo "$OLLAMA_LISTEN" | grep -qE '\*:|0\.0\.0\.0:'; then
        issue "Ollama is currently listening on ALL interfaces"
        echo -e "  ${DIM}Restart Ollama after fixing OLLAMA_HOST to apply${NC}"
    elif [[ -n "$OLLAMA_LISTEN" ]]; then
        ok "Ollama is listening on localhost only"
    fi
fi

# ─── Docker ───
header "Docker"
if docker info >/dev/null 2>&1; then
    info "Docker is running"
    # Check for Open WebUI or other exposed containers
    EXPOSED=$(docker ps --format '{{.Ports}} {{.Names}}' 2>/dev/null | grep "0.0.0.0:" || true)
    if [[ -n "$EXPOSED" ]]; then
        warn "Containers with ports exposed on all interfaces:"
        echo "$EXPOSED" | sed 's/^/  /'
        echo -e "  ${DIM}Consider binding to 127.0.0.1 instead (e.g., -p 127.0.0.1:8080:8080)${NC}"
    fi
else
    # Check for orphaned daemons
    if [[ -f "/Library/LaunchDaemons/com.docker.socket.plist" ]] || [[ -f "/Library/LaunchDaemons/com.docker.vmnetd.plist" ]]; then
        warn "Docker LaunchDaemons found but Docker is not running"
        if $FIX_MODE && [[ $EUID -eq 0 ]]; then
            rm -f /Library/LaunchDaemons/com.docker.socket.plist /Library/LaunchDaemons/com.docker.vmnetd.plist 2>/dev/null && {
                fixed "Removed orphaned Docker LaunchDaemons"
                ((FIXED++))
            }
        else
            echo -e "  ${DIM}Fix: sudo rm /Library/LaunchDaemons/com.docker.{socket,vmnetd}.plist${NC}"
        fi
    else
        ok "Docker is not installed/running"
    fi
fi

# ─── Listening Ports ───
header "Listening Ports"
echo ""
if command -v lsof &>/dev/null; then
    LISTEN_OUTPUT=$(lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null || true)
    if [[ -n "$LISTEN_OUTPUT" ]]; then
        WILDCARD=$(echo "$LISTEN_OUTPUT" | grep -E '\*:|0\.0\.0\.0:' | grep -v "localhost" || true)
        echo "$LISTEN_OUTPUT" | head -1
        echo "$LISTEN_OUTPUT" | tail -n +2 | sort -t: -k2 -n
        echo ""
        if [[ -n "$WILDCARD" ]]; then
            warn "Bound to ALL interfaces (not just localhost):"
            echo "$WILDCARD" | awk '{printf "  %-15s %s %s\n", $1, $8, $9}'
        fi
    else
        ok "No listening TCP ports found"
    fi
fi

# ─── Running AI Processes ───
header "Running AI Processes"
AGENT_PATTERNS="ollama|llama|openclaw|zeroclaw|picoclaw|openwebui|open-webui|langchain|autogpt|openinterpreter|open.interpreter|comfy|stable.diffusion|whisper|vllm|llamacpp|llama.cpp|llama-server|kobold|textgen|oobabooga|lmstudio|localai|jan\.ai|msty|gpt4all|anything-llm"
AGENT_PROCS=$(ps aux | grep -iE "$AGENT_PATTERNS" | grep -v grep || true)
if [[ -n "$AGENT_PROCS" ]]; then
    info "Found AI/agent processes:"
    echo "$AGENT_PROCS" | awk '{printf "  PID %-7s %5s%% MEM  %s\n", $2, $4, $11}'
else
    ok "No AI agent processes detected"
fi

# ─── Tailscale ───
header "Tailscale"
if command -v tailscale &>/dev/null || [[ -f "/Applications/Tailscale.app/Contents/MacOS/Tailscale" ]]; then
    TS_BIN="tailscale"
    [[ -f "/Applications/Tailscale.app/Contents/MacOS/Tailscale" ]] && TS_BIN="/Applications/Tailscale.app/Contents/MacOS/Tailscale"

    TS_STATUS=$($TS_BIN status 2>/dev/null || true)
    if [[ -n "$TS_STATUS" ]]; then
        info "Tailscale is active"
        TS_IP=$($TS_BIN ip -4 2>/dev/null || echo "unknown")
        info "  Tailscale IP: $TS_IP"

        # Check for tailscale serve/funnel
        TS_SERVE=$($TS_BIN serve status 2>/dev/null || true)
        if [[ -n "$TS_SERVE" && "$TS_SERVE" != *"No"* ]]; then
            warn "Tailscale Serve is active — verify exposed services:"
            echo "$TS_SERVE" | sed 's/^/  /'
        fi

        TS_FUNNEL=$($TS_BIN funnel status 2>/dev/null || true)
        if [[ -n "$TS_FUNNEL" && "$TS_FUNNEL" != *"No"* && "$TS_FUNNEL" != *"off"* ]]; then
            issue "Tailscale Funnel is active — services exposed to public internet"
            echo "$TS_FUNNEL" | sed 's/^/  /'
        fi
    else
        ok "Tailscale installed but not connected"
    fi
else
    ok "Tailscale not installed"
fi

# ─── LaunchAgents (User) ───
header "User LaunchAgents"
LA_DIR="$HOME/Library/LaunchAgents"
if [[ -d "$LA_DIR" ]]; then
    CUSTOM_AGENTS=0
    while IFS= read -r plist; do
        [[ -z "$plist" ]] && continue
        NAME=$(basename "$plist" .plist)
        if echo "$NAME" | grep -qiE '^com\.(apple|google|microsoft|adobe|spotify)'; then
            continue
        fi
        KEEP_ALIVE=$(defaults read "$plist" KeepAlive 2>/dev/null || echo "")
        LOADED=$(launchctl list 2>/dev/null | grep "$NAME" || true)
        STATUS="not loaded"
        [[ -n "$LOADED" ]] && STATUS="LOADED"

        if [[ "$KEEP_ALIVE" == "1" ]]; then
            warn "$NAME — $STATUS, KeepAlive=true (auto-restarts)"
        else
            info "$NAME — $STATUS"
        fi
        ((CUSTOM_AGENTS++))
    done < <(find "$LA_DIR" -name "*.plist" -maxdepth 1 2>/dev/null)

    if [[ $CUSTOM_AGENTS -eq 0 ]]; then
        ok "No custom LaunchAgents found"
    fi
else
    ok "No LaunchAgents directory"
fi

# ─── LaunchDaemons (System) ───
header "System LaunchDaemons"
LD_DIR="/Library/LaunchDaemons"
if [[ -d "$LD_DIR" ]]; then
    CUSTOM_DAEMONS=0
    while IFS= read -r plist; do
        [[ -z "$plist" ]] && continue
        NAME=$(basename "$plist" .plist)
        if echo "$NAME" | grep -qiE '^com\.apple\.'; then
            continue
        fi
        info "$NAME"
        ((CUSTOM_DAEMONS++))
    done < <(find "$LD_DIR" -name "*.plist" -maxdepth 1 2>/dev/null)

    if [[ $CUSTOM_DAEMONS -eq 0 ]]; then
        ok "No third-party LaunchDaemons found"
    fi
else
    ok "No LaunchDaemons directory"
fi

# ─── Cron Jobs ───
header "Cron Jobs"
CRON=$(crontab -l 2>/dev/null || true)
if [[ -n "$CRON" ]]; then
    warn "User crontab has entries:"
    echo "$CRON" | sed 's/^/  /'
else
    ok "No user cron jobs"
fi

# ─── Login Items ───
header "Login Items"
LOGIN_ITEMS=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "")
if [[ -n "$LOGIN_ITEMS" && "$LOGIN_ITEMS" != "" ]]; then
    info "Login items: $LOGIN_ITEMS"
else
    ok "No login items"
fi

# ─── Home Directory Permissions ───
header "Home Directory Permissions"
HOME_PERMS=$(stat -f "%Lp" "$HOME" 2>/dev/null || stat -c "%a" "$HOME" 2>/dev/null)
if [[ "$HOME_PERMS" == "700" ]]; then
    ok "Home directory is 700 (owner-only)"
elif [[ "$HOME_PERMS" == "750" || "$HOME_PERMS" == "755" ]]; then
    warn "Home directory is $HOME_PERMS — should be 700"
    if $FIX_MODE; then
        chmod 700 "$HOME"
        fixed "Home directory set to 700"
        ((FIXED++))
    else
        echo -e "  ${DIM}Fix: chmod 700 ~/  ${NC}"
    fi
else
    info "Home directory permissions: $HOME_PERMS"
fi

# ─── SSH Config ───
header "SSH Configuration"
if [[ -d "$HOME/.ssh" ]]; then
    SSH_PERMS=$(stat -f "%Lp" "$HOME/.ssh" 2>/dev/null)
    if [[ "$SSH_PERMS" == "700" ]]; then
        ok ".ssh directory is 700"
    else
        issue ".ssh directory is $SSH_PERMS — should be 700"
        if $FIX_MODE; then
            chmod 700 "$HOME/.ssh"
            fixed ".ssh directory set to 700"
            ((FIXED++))
        fi
    fi

    if [[ -f "$HOME/.ssh/authorized_keys" ]]; then
        KEY_COUNT=$(grep -c "^ssh-" "$HOME/.ssh/authorized_keys" 2>/dev/null || echo "0")
        warn "authorized_keys has $KEY_COUNT key(s) — verify these are yours"
    else
        ok "No authorized_keys file"
    fi

    while IFS= read -r keyfile; do
        [[ -z "$keyfile" ]] && continue
        KPERMS=$(stat -f "%Lp" "$keyfile" 2>/dev/null)
        if [[ "$KPERMS" != "600" && "$KPERMS" != "400" ]]; then
            issue "$(basename "$keyfile") has permissions $KPERMS — should be 600"
            if $FIX_MODE; then
                chmod 600 "$keyfile"
                fixed "$(basename "$keyfile") set to 600"
                ((FIXED++))
            fi
        fi
    done < <(find "$HOME/.ssh" -name "id_*" ! -name "*.pub" 2>/dev/null)
else
    ok "No .ssh directory"
fi

# ─── Sensitive Files ───
header "Sensitive Files Check"
SENSITIVE_PATTERNS=(".env" ".env.local" ".env.production" "credentials.json" "service-account*.json" ".netrc" ".npmrc")
for pat in "${SENSITIVE_PATTERNS[@]}"; do
    FOUND=$(find "$HOME" -maxdepth 3 -name "$pat" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -5 || true)
    if [[ -n "$FOUND" ]]; then
        warn "Found $pat files:"
        echo "$FOUND" | sed 's/^/  /'
    fi
done

# ─── Software Updates ───
header "Software Updates"
UPDATE_CHECK=$(softwareupdate -l 2>&1 || true)
if echo "$UPDATE_CHECK" | grep -q "No new software available"; then
    ok "macOS is up to date"
else
    warn "Software updates may be available — run: softwareupdate -l"
fi

# ─── Power/Sleep Settings ───
header "Power Management"
SLEEP_VAL=$(pmset -g | grep '^ sleep' | awk '{print $2}' 2>/dev/null || echo "unknown")
DISPLAY_SLEEP=$(pmset -g | grep '^ displaysleep' | awk '{print $2}' 2>/dev/null || echo "unknown")
AUTORESTART=$(pmset -g | grep '^ autorestart' | awk '{print $2}' 2>/dev/null || echo "unknown")

if [[ "$SLEEP_VAL" == "0" ]]; then
    ok "System sleep disabled (expected for always-on server)"
else
    warn "System sleep: $SLEEP_VAL min — consider disabling for always-on AI workstation"
    echo -e "  ${DIM}Fix: sudo pmset -a sleep 0${NC}"
fi

if [[ "$AUTORESTART" == "1" ]]; then
    ok "Auto-restart on power failure is enabled"
else
    warn "Auto-restart on power failure is disabled"
    if $FIX_MODE && [[ $EUID -eq 0 ]]; then
        pmset -a autorestart 1 2>/dev/null
        fixed "Auto-restart enabled"
        ((FIXED++))
    else
        echo -e "  ${DIM}Fix: sudo pmset -a autorestart 1${NC}"
    fi
fi

# ─── Summary ───
header "Audit Complete"
echo ""
if [[ $ISSUES -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}No critical issues found.${NC}"
else
    echo -e "  ${RED}${BOLD}Found $ISSUES critical issue(s) that should be addressed.${NC}"
fi
if $FIX_MODE && [[ $FIXED -gt 0 ]]; then
    echo -e "  ${GREEN}${BOLD}Auto-fixed $FIXED issue(s).${NC}"
fi
if ! $FIX_MODE && [[ $ISSUES -gt 0 ]]; then
    echo -e "  ${DIM}Run with --fix to auto-fix applicable issues.${NC}"
fi
echo ""
