#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$PROJECT_ROOT/.env" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$PROJECT_ROOT/.env"
    set +a
fi

WAN_IF="${WAN_IF:-enx0237677e7807}"
LAN_IF="${LAN_IF:-wlo1}"
HTTP_REDIRECT_PORT="${HTTP_REDIRECT_PORT:-8080}"
HTTPS_PORT="${HTTPS_PORT:-8443}"

SERVER_SCRIPT="$SCRIPT_DIR/server.py"
SERVER_PID_FILE="/tmp/captive-server.pid"
SERVER_LOG="/tmp/captive-server.log"

BACKUP_DIR="/tmp/captive-router"
IPTABLES_BACKUP="$BACKUP_DIR/iptables.backup"
SYSCTL_BACKUP="$BACKUP_DIR/ip_forward"

usage() {
    echo "Uso: sudo $0 {start|stop}"
    exit 1
}

require_root() {
    [[ "$(id -u)" -eq 0 ]] || { echo "Ejecuta como root."; exit 1; }
}

start_server() {
    if [[ -f "$SERVER_PID_FILE" ]] && kill -0 "$(cat "$SERVER_PID_FILE")" 2>/dev/null; then
        echo "Servidor ya está activo (PID $(cat "$SERVER_PID_FILE"))."
        return
    fi
    echo "Iniciando servidor del portal..."
    nohup bash -c "cd '$PROJECT_ROOT' && PYTHONPATH='$PROJECT_ROOT' exec python3 '$SERVER_SCRIPT'" >>"$SERVER_LOG" 2>&1 &
    echo $! >"$SERVER_PID_FILE"
}

stop_server() {
    if [[ -f "$SERVER_PID_FILE" ]]; then
        local pid
        pid="$(cat "$SERVER_PID_FILE")"
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            wait "$pid" 2>/dev/null || true
        fi
        rm -f "$SERVER_PID_FILE"
    fi
}

open_login() {
    local url="https://127.0.0.1:${HTTPS_PORT}/login"
    if command -v xdg-open >/dev/null; then
        xdg-open "$url" >/dev/null 2>&1 || true
    elif command -v open >/dev/null; then
        open "$url" >/dev/null 2>&1 || true
    else
        echo "Abre $url en tu navegador."
    fi
}

start_router() {
    echo "Activando modo portal..."
    mkdir -p "$BACKUP_DIR"
    [[ -f "$IPTABLES_BACKUP" ]] || iptables-save >"$IPTABLES_BACKUP"
    [[ -f "$SYSCTL_BACKUP" ]] || cat /proc/sys/net/ipv4/ip_forward >"$SYSCTL_BACKUP"

    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD DROP
    iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -p udp --dport 53 -j ACCEPT
    iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -p tcp --dport 53 -j ACCEPT
    iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
    iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -A PREROUTING -i "$LAN_IF" -p tcp --dport 80 -j REDIRECT --to-port "$HTTP_REDIRECT_PORT"

    start_server
    open_login
    echo "Portal cautivo activo en https://127.0.0.1:${HTTPS_PORT}/login"
}

stop_router() {
    echo "Restaurando configuración..."
    if [[ -f "$IPTABLES_BACKUP" ]]; then
        iptables-restore <"$IPTABLES_BACKUP"
        rm -f "$IPTABLES_BACKUP"
    fi
    if [[ -f "$SYSCTL_BACKUP" ]]; then
        sysctl -w net.ipv4.ip_forward="$(cat "$SYSCTL_BACKUP")" >/dev/null
        rm -f "$SYSCTL_BACKUP"
    fi
    rmdir "$BACKUP_DIR" 2>/dev/null || true
    stop_server
    echo "Portal cautivo detenido."
}

require_root

case "${1:-}" in
    start) start_router ;;
    stop) stop_router ;;
    *) usage ;;
esac
