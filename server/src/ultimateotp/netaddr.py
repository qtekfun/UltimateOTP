# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""IP address and network helpers."""

import ipaddress

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_networks(text: str) -> tuple[IpNetwork, ...]:
    """Comma-separated CIDRs (a bare address is a /32 or /128). Raises ValueError."""
    return tuple(
        ipaddress.ip_network(part.strip(), strict=False) for part in text.split(",") if part.strip()
    )


def parse_ip(text: str | None) -> IpAddress | None:
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def in_networks(host: str | None, networks: tuple[IpNetwork, ...]) -> bool:
    address = parse_ip(host)
    return address is not None and any(address in network for network in networks)
