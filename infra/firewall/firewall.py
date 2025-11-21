import os
import shutil
import subprocess

from helpers.env_loader import load_env_file
from helpers.ip_mac import validate_ip, validate_mac

load_env_file()

LAN_IF = os.getenv("LAN_IF", "wlan0")
WAN_IF = os.getenv("WAN_IF", "eth0")


def _run_iptables(args):
    cmd = ["iptables"] + args
    # Para debug:
    print("[iptables]", " ".join(cmd))
    subprocess.run(cmd, check=True)


def _flush_conntrack(ip: str) -> None:
    """
    Elimina entradas de conntrack para la IP para que no sigan vivas
    conexiones ya establecidas después de cerrar sesión.
    """
    conntrack_bin = shutil.which("conntrack")
    if not conntrack_bin:
        print("[conntrack] comando no encontrado, no se limpiaron entradas")
        return

    for flag in ("-s", "-d"):  # salida y posible tráfico entrante
        cmd = [conntrack_bin, "-D", "-f", "ipv4", flag, ip]
        try:
            subprocess.run(cmd, check=True)
            print(f"[conntrack] Limpias entradas {flag} {ip}")
        except subprocess.CalledProcessError as exc:
            print(f"[conntrack] No se pudieron limpiar conntrack {flag} {ip}: {exc}")


def allow_client_in_firewall(ip: str, mac: str | None = None):
    validate_ip(ip)
    if mac is not None:
        validate_mac(mac)

    args = [
        "-A", "FORWARD",          # añadir regla al final de la cadena FORWARD
        "-i", LAN_IF,             # desde la interfaz de clientes
        "-o", WAN_IF,             # hacia la interfaz que sale a Internet
        "-s", ip,                 # IP de origen del cliente
    ]

    if mac is not None:
        args += [
            "-m", "mac",
            "--mac-source", mac,
        ]

    args += ["-j", "ACCEPT"]

    _run_iptables(args)
    _flush_conntrack(ip)


def deny_client_in_firewall(ip: str, mac: str | None = None):
    validate_ip(ip)
    if mac is not None:
        validate_mac(mac)

    args = [
        "-D", "FORWARD",          # eliminar esa regla
        "-i", LAN_IF,
        "-o", WAN_IF,
        "-s", ip,
    ]

    if mac is not None:
        args += [
            "-m", "mac",
            "--mac-source", mac,
        ]

    args += ["-j", "ACCEPT"]

    _run_iptables(args)
    _flush_conntrack(ip)
