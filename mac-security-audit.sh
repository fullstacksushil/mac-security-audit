#!/bin/bash
# mac-security-audit.sh — Security audit for macOS systems
# Run: chmod +x mac-security-audit.sh && ./mac-security-audit.sh
# Use sudo for full audit: sudo ./mac-security-audit.sh

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $1"; }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
alert() { echo -e "${RED}[ALERT]${NC} $1"; }
header(){ echo -e "\n${BOLD}═══ $1 ═══${NC}"; }

ISSUES=0
issue() { alert "$1"; ((ISSUES++)); }

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
        issue "Firewall is DISABLED — enable in System Settings > Network > Firewall"
    fi

    STEALTH=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)
    if echo "$STEALTH" | grep -q "enabled"; then
        ok "Stealth mode is enabled"
    else
        warn "Stealth mode is disabled (machine responds to pings)"
    fi
else
    warn "Run with sudo to check firewall status"
fi

# ─── FileVault ───
header "FileVault (Disk Encryption)"
FV_STATUS=$(fdesetup status 2>/dev/null || echo "unknown")
if echo "$FV_STATUS" | grep -q "On"; then
    ok "FileVault is ON"
else
    issue "FileVault is OFF — your disk is not encrypted"
fi

# ─── SIP (System Integrity Protection) ───
header "System Integrity Protection"
SIP_STATUS=$(csrutil status 2>/dev/null || echo "unknown")
if echo "$SIP_STATUS" | grep -q "enabled"; then
    ok "SIP is enabled"
else
    issue "SIP is DISABLED — re-enable from Recovery Mode"
fi

# ─── Gatekeeper ───
header "Gatekeeper"
GK_STATUS=$(spctl --status 2>/dev/null || echo "unknown")
if echo "$GK_STATUS" | grep -q "enabled"; then
    ok "Gatekeeper is enabled"
else
    issue "Gatekeeper is DISABLED"
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

# SSH
if systemsetup -getremotelogin 2>/dev/null | grep -qi "on"; then
    issue "Remote Login (SSH) is ENABLED"
else
    ok "Remote Login (SSH) is disabled"
fi

# Screen Sharing / VNC
if [[ $EUID -eq 0 ]]; then
    check_sharing "com.apple.screensharing" "Screen Sharing"
    check_sharing "com.apple.RemoteDesktop" "Remote Desktop (ARD)"
else
    warn "Run with sudo to check sharing services"
fi

# ─── Listening Ports ───
header "Listening Ports"
echo ""
if command -v lsof &>/dev/null; then
    LISTEN_OUTPUT=$(lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null || true)
    if [[ -n "$LISTEN_OUTPUT" ]]; then
        # Check for wildcard bindings (0.0.0.0 or *)
        WILDCARD=$(echo "$LISTEN_OUTPUT" | grep -E '\*:|0\.0\.0\.0:' | grep -v "localhost" || true)
        echo "$LISTEN_OUTPUT" | head -1
        echo "$LISTEN_OUTPUT" | tail -n +2 | sort -t: -k2 -n
        echo ""
        if [[ -n "$WILDCARD" ]]; then
            warn "The following are bound to ALL interfaces (not just localhost):"
            echo "$WILDCARD" | awk '{printf "  %-15s %s %s\n", $1, $8, $9}'
        fi
    else
        ok "No listening TCP ports found"
    fi
fi

# ─── Running Agents/Bots ───
header "Running Agents & AI Services"
AGENT_PATTERNS="ollama|llama|openclaw|zeroclaw|picoclaw|openwebui|open-webui|telegram|bot|langchain|autogpt|openinterpreter|interpreter|comfy|stable.diffusion|whisper|vllm|llamacpp|llama.cpp|kobold|textgen|oobabooga|lmstudio"
AGENT_PROCS=$(ps aux | grep -iE "$AGENT_PATTERNS" | grep -v grep || true)
if [[ -n "$AGENT_PROCS" ]]; then
    info "Found AI/agent processes:"
    echo "$AGENT_PROCS" | awk '{printf "  PID %-7s %-5s%% MEM  %s\n", $2, $4, $11}'
else
    ok "No AI agent processes detected"
fi

# ─── LaunchAgents (User) ───
header "User LaunchAgents (~Library/LaunchAgents)"
LA_DIR="$HOME/Library/LaunchAgents"
if [[ -d "$LA_DIR" ]]; then
    CUSTOM_AGENTS=0
    while IFS= read -r plist; do
        [[ -z "$plist" ]] && continue
        NAME=$(basename "$plist" .plist)
        # Skip known Apple/system agents
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
header "System LaunchDaemons (/Library/LaunchDaemons)"
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
    warn "Home directory is $HOME_PERMS — consider: chmod 700 ~/"
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
    fi

    # Check for authorized_keys
    if [[ -f "$HOME/.ssh/authorized_keys" ]]; then
        KEY_COUNT=$(grep -c "^ssh-" "$HOME/.ssh/authorized_keys" 2>/dev/null || echo "0")
        warn "authorized_keys has $KEY_COUNT key(s) — verify these are yours"
    else
        ok "No authorized_keys file"
    fi

    # Check key files permissions
    while IFS= read -r keyfile; do
        [[ -z "$keyfile" ]] && continue
        KPERMS=$(stat -f "%Lp" "$keyfile" 2>/dev/null)
        if [[ "$KPERMS" != "600" && "$KPERMS" != "400" ]]; then
            issue "$(basename "$keyfile") has permissions $KPERMS — should be 600"
        fi
    done < <(find "$HOME/.ssh" -name "id_*" ! -name "*.pub" 2>/dev/null)
else
    ok "No .ssh directory"
fi

# ─── Sensitive Files in Home ───
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
if [[ "$SLEEP_VAL" == "0" ]]; then
    warn "System sleep is disabled (machine never sleeps)"
else
    ok "System sleep: $SLEEP_VAL minutes"
fi
if [[ "$DISPLAY_SLEEP" == "0" ]]; then
    warn "Display sleep is disabled"
else
    ok "Display sleep: $DISPLAY_SLEEP minutes"
fi

# ─── Summary ───
header "Audit Complete"
if [[ $ISSUES -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}No critical issues found.${NC}"
else
    echo -e "${RED}${BOLD}Found $ISSUES critical issue(s) that should be addressed.${NC}"
fi
echo ""
