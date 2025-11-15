import ipaddress
import re

MAC_REGEX = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
LAN_IF = "wlan0"  # tiene que coincidir con tu interfaz de cliente #TODO:


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



##TODO: BORRAR LO SIGUIENTE SI AL FINAL NO SE VA A USAR
# Otra forma de obtener la mac a traves de comandos

import subprocess

def get_mac_for_ip_cmd(ip: str, iface: str = LAN_IF) -> str | None:
    validate_ip(ip)
    out = subprocess.check_output(
        ["ip", "neigh", "show", "dev", iface, ip],
        text=True
    )
    # Ejemplo de salida:
    # 192.168.42.10 lladdr aa:bb:cc:dd:ee:ff REACHABLE
    parts = out.split()
    if "lladdr" in parts:
        idx = parts.index("lladdr")
        return parts[idx + 1].lower()
    return None