"""
oui_lookup.py -- offline MAC-vendor (OUI) resolution.

No network access is performed. A small built-in table of common IEEE OUI
prefixes (the first 24 bits of a MAC address) is used to map a MAC to a likely
hardware vendor. This is intentionally compact -- it covers the manufacturers
you typically meet on a home/office LAN (routers, phones, laptops, IoT, VMs)
rather than the full IEEE registry.

Public API:
    lookup_vendor(mac)        -> vendor string ("" if unknown)
    is_locally_administered(mac) -> True for randomized/locally-assigned MACs
    annotate(mac)             -> vendor, or a "(random)" marker for LAA MACs

Usage:
    >>> from oui_lookup import lookup_vendor
    >>> lookup_vendor("3c:5a:b4:11:22:33")
    'Google'
    >>> lookup_vendor("aa:bb:cc:dd:ee:ff")
    ''
"""

from typing import Dict

__all__ = ["lookup_vendor", "is_locally_administered", "annotate", "OUI_TABLE"]


# OUI prefix (lower-case, colon-free, 6 hex digits) -> vendor name.
# Sourced from well-known publicly documented IEEE assignments. Kept small on
# purpose so the toolkit stays dependency-free and offline.
OUI_TABLE: Dict[str, str] = {
    # Apple
    "001451": "Apple", "0017f2": "Apple", "0019e3": "Apple", "001b63": "Apple",
    "001e52": "Apple", "0021e9": "Apple", "002332": "Apple", "0025bc": "Apple",
    "002500": "Apple", "0026bb": "Apple", "3c0754": "Apple", "a4d1d2": "Apple",
    "ac87a3": "Apple", "b8e856": "Apple", "f0d1a9": "Apple", "f80377": "Apple",
    "f4f15a": "Apple", "8866a5": "Apple", "dca904": "Apple", "98fe94": "Apple",
    # Samsung
    "0012fb": "Samsung", "001632": "Samsung", "0018af": "Samsung",
    "001d25": "Samsung", "002399": "Samsung", "0026e2": "Samsung",
    "5001bb": "Samsung", "8425db": "Samsung", "bc8385": "Samsung",
    "e8508b": "Samsung", "f409d8": "Samsung", "fcc734": "Samsung",
    # Google / Nest
    "3c5ab4": "Google", "94eb2c": "Google", "f4f5d8": "Google",
    "f4f5e8": "Google", "001a11": "Google", "d8e0e1": "Google",
    "a47733": "Google", "54600d": "Google",
    # Intel (NICs, laptops)
    "001517": "Intel", "0019d1": "Intel", "001b21": "Intel", "001e67": "Intel",
    "0021ff": "Intel", "0024d7": "Intel", "3c970e": "Intel", "7c7a91": "Intel",
    "a0a8cd": "Intel", "e4a471": "Intel", "8c1645": "Intel", "94659c": "Intel",
    # Raspberry Pi Foundation
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
    "28cdc1": "Raspberry Pi", "d83add": "Raspberry Pi",
    # TP-Link
    "001de5": "TP-Link", "1c61b4": "TP-Link", "50c7bf": "TP-Link",
    "5c628b": "TP-Link", "60e327": "TP-Link", "a42bb0": "TP-Link",
    "ac84c6": "TP-Link", "e848b8": "TP-Link", "f4f26d": "TP-Link",
    # Netgear
    "00146c": "Netgear", "001e2a": "Netgear", "002690": "Netgear",
    "20e52a": "Netgear", "9c3dcf": "Netgear", "c03f0e": "Netgear",
    "a040a0": "Netgear",
    # D-Link
    "001346": "D-Link", "001cf0": "D-Link", "00226b": "D-Link",
    "1cbdb9": "D-Link", "28107b": "D-Link", "ccb255": "D-Link",
    # ASUS / ASUSTek
    "001bfc": "ASUSTek", "002354": "ASUSTek", "04d4c4": "ASUSTek",
    "1c872c": "ASUSTek", "2c56dc": "ASUSTek", "ac220b": "ASUSTek",
    "d850e6": "ASUSTek",
    # Cisco / Cisco-Linksys
    "00000c": "Cisco", "000142": "Cisco", "0007eb": "Cisco", "001121": "Cisco",
    "0018ba": "Cisco", "001e79": "Cisco", "00264a": "Cisco", "58bc27": "Cisco",
    "002369": "Linksys", "48f8b3": "Linksys", "c0c1c0": "Linksys",
    # Ubiquiti
    "002722": "Ubiquiti", "0418d6": "Ubiquiti", "245a4c": "Ubiquiti",
    "44d9e7": "Ubiquiti", "788a20": "Ubiquiti", "fcecda": "Ubiquiti",
    "f09fc2": "Ubiquiti", "b4fbe4": "Ubiquiti",
    # Amazon (Echo / Kindle / Fire)
    "0c47c9": "Amazon", "34d270": "Amazon", "44650d": "Amazon",
    "68543d": "Amazon", "747548": "Amazon", "a002dc": "Amazon",
    "fca667": "Amazon", "f0272d": "Amazon",
    # Microsoft (Surface / Xbox / Hyper-V vNIC)
    "0017fa": "Microsoft", "001dd8": "Microsoft", "00155d": "Microsoft (Hyper-V)",
    "0050f2": "Microsoft", "7c1e52": "Microsoft", "c83f26": "Microsoft",
    # Sony
    "0013a9": "Sony", "001a80": "Sony", "0024be": "Sony", "fc0fe6": "Sony",
    "a8e3ec": "Sony",
    # Huawei
    "001882": "Huawei", "00259e": "Huawei", "286ed4": "Huawei",
    "4c5499": "Huawei", "70723c": "Huawei", "ac4e91": "Huawei",
    # Xiaomi
    "286c07": "Xiaomi", "3480b3": "Xiaomi", "640980": "Xiaomi",
    "742344": "Xiaomi", "f48b32": "Xiaomi", "fc64ba": "Xiaomi",
    # Espressif (ESP8266 / ESP32 IoT)
    "240ac4": "Espressif", "2462ab": "Espressif", "3c71bf": "Espressif",
    "5ccf7f": "Espressif", "807d3a": "Espressif", "a4cf12": "Espressif",
    "bcddc2": "Espressif", "ecfabc": "Espressif",
    # Virtualization vendors
    "000569": "VMware", "000c29": "VMware", "001c14": "VMware",
    "005056": "VMware", "080027": "VirtualBox", "0a0027": "VirtualBox",
    "525400": "QEMU/KVM", "00163e": "Xen",
    # Misc common consumer/IoT
    "001788": "Philips Hue", "ecb5fa": "Philips Hue",
    "b0c554": "Roku", "dca266": "Roku", "cc6da0": "Roku",
    "d0034b": "Honeywell", "001124": "HP", "0017a4": "HP", "3c4a92": "HP",
    "94570e": "HP", "0004f2": "Polycom",
}


def _clean(mac: str) -> str:
    """Return the lower-case hex-only digits of a MAC address."""
    if not mac:
        return ""
    return "".join(c for c in mac.lower() if c in "0123456789abcdef")


def is_locally_administered(mac: str) -> bool:
    """
    True when the MAC is locally administered (LAA) -- bit 1 of the first
    octet is set. Modern phones/laptops emit randomized LAA MACs for privacy,
    so these can never match a real vendor OUI.
    """
    hexs = _clean(mac)
    if len(hexs) < 2:
        return False
    try:
        first_octet = int(hexs[:2], 16)
    except ValueError:
        return False
    return bool(first_octet & 0x02)


def lookup_vendor(mac: str) -> str:
    """
    Map a MAC address to a vendor name using the built-in OUI table.
    Returns "" when the prefix is unknown. No network access.
    """
    hexs = _clean(mac)
    if len(hexs) < 6:
        return ""
    return OUI_TABLE.get(hexs[:6], "")


def annotate(mac: str) -> str:
    """
    Human-friendly vendor label: the resolved vendor, or "(random MAC)" for
    locally administered addresses with no OUI match, or "" otherwise.
    """
    vendor = lookup_vendor(mac)
    if vendor:
        return vendor
    if is_locally_administered(mac):
        return "(random MAC)"
    return ""


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python oui_lookup.py <mac> [<mac> ...]")
        print(f"built-in OUI entries: {len(OUI_TABLE)}")
        raise SystemExit(0)

    for m in sys.argv[1:]:
        label = annotate(m) or "(unknown)"
        print(f"{m:<20} -> {label}")
