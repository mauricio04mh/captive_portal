import re
import ipaddress
import subprocess

from helpers.ip_mac import validate_ip, validate_mac

LAN_IF = "wlan0"   # TODO: esto va en el .env y debe coincidir con el script de bash
WAN_IF = "eth0"   


def _run_iptables(args):
    cmd = ["iptables"] + args
    # Para debug:
    print("[iptables]", " ".join(cmd))
    subprocess.run(cmd, check=True)


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
