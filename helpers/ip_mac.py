import ipaddress
import os
import re

from helpers.env_loader import load_env_file

load_env_file()

MAC_REGEX = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
LAN_IF = os.getenv("LAN_IF", "wlan0") 


def validate_ip(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"IP inválida: {ip!r}")


def validate_mac(mac: str):
    if not MAC_REGEX.match(mac):
        raise ValueError(f"MAC inválida: {mac!r}")


def get_mac_for_ip(ip: str, iface: str = LAN_IF) -> str | None:
    """
    Devuelve la MAC asociada a una IP mirando /proc/net/arp.
    Si no la encuentra, devuelve None.
    """
    validate_ip(ip)

    try:
        with open("/proc/net/arp", "r") as f:
            next(f)  # saltar cabecera
            for line in f:
                fields = line.split()
                if len(fields) < 6:
                    continue

                ip_addr, hw_type, flags, mac, mask, device = fields

                if ip_addr == ip and device == iface and mac != "00:00:00:00:00:00":
                    return mac.lower()
    except FileNotFoundError:
        # No es Linux o no existe /proc/net/arp
        return None

    return None
