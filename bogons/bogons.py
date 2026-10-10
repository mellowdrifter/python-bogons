#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python library to validate IP and ASN bogons, with modern RFC descriptions.
"""

from __future__ import annotations

import ipaddress
from typing import Tuple, Union

# IPv4 bogon rules with RFC descriptions
V4_BOGON_RULES: Tuple[Tuple[ipaddress.IPv4Network, str], ...] = (
    (ipaddress.IPv4Network("0.0.0.0/8"), "RFC 1122 (This Host on This Network)"),
    (ipaddress.IPv4Network("10.0.0.0/8"), "RFC 1918 (Private-Use)"),
    (ipaddress.IPv4Network("100.64.0.0/10"), "RFC 6598 (Shared Address Space / CGNAT)"),
    (ipaddress.IPv4Network("127.0.0.0/8"), "RFC 1122 (Loopback)"),
    (ipaddress.IPv4Network("169.254.0.0/16"), "RFC 3927 (Link-Local)"),
    (ipaddress.IPv4Network("172.16.0.0/12"), "RFC 1918 (Private-Use)"),
    # Specific 192.0.0.0/24 sub-allocations
    (ipaddress.IPv4Network("192.0.0.170/31"), "RFC 8880 (NAT64/DNS64 Discovery)"),
    (ipaddress.IPv4Network("192.0.0.10/32"), "RFC 8155 (TURN Anycast)"),
    (ipaddress.IPv4Network("192.0.0.9/32"), "RFC 7725 (PCP Anycast)"),
    (ipaddress.IPv4Network("192.0.0.8/32"), "RFC 7600 (IPv4 Dummy Address)"),
    (ipaddress.IPv4Network("192.0.0.0/29"), "RFC 6333 / RFC 7335 (DS-Lite / Dual-Stack Continuity)"),
    (ipaddress.IPv4Network("192.0.0.0/24"), "RFC 6890 (IETF Protocol Assignments)"),
    (ipaddress.IPv4Network("192.0.2.0/24"), "RFC 5737 (Documentation TEST-NET-1)"),
    (ipaddress.IPv4Network("192.31.196.0/24"), "RFC 7535 (AS112-v4)"),
    (ipaddress.IPv4Network("192.52.193.0/24"), "RFC 7450 (Automatic Multicast Tunneling - AMT)"),
    (ipaddress.IPv4Network("192.88.99.0/24"), "RFC 7526 (6to4 Relay Anycast - Deprecated)"),
    (ipaddress.IPv4Network("192.168.0.0/16"), "RFC 1918 (Private-Use)"),
    (ipaddress.IPv4Network("198.18.0.0/15"), "RFC 2544 (Benchmarking)"),
    (ipaddress.IPv4Network("198.51.100.0/24"), "RFC 5737 (Documentation TEST-NET-2)"),
    (ipaddress.IPv4Network("203.0.113.0/24"), "RFC 5737 (Documentation TEST-NET-3)"),
    (ipaddress.IPv4Network("224.0.0.0/4"), "RFC 1112 (Multicast)"),
    (ipaddress.IPv4Network("255.255.255.255/32"), "RFC 919 / RFC 8190 (Limited Broadcast)"),
    (ipaddress.IPv4Network("240.0.0.0/4"), "RFC 1112 (Reserved / Former Class E)"),
)

# IPv6 bogon rules with RFC descriptions
V6_BOGON_RULES: Tuple[Tuple[ipaddress.IPv6Network, str], ...] = (
    (ipaddress.IPv6Network("2001:db8::/32"), "RFC 3849 (Documentation)"),
    (ipaddress.IPv6Network("2001::/32"), "RFC 4380 (Teredo)"),
    (ipaddress.IPv6Network("2001:1::1/128"), "RFC 7723 (PCP Anycast)"),
    (ipaddress.IPv6Network("2001:1::2/128"), "RFC 8155 (TURN Anycast)"),
    (ipaddress.IPv6Network("2001:2::/48"), "RFC 5180 / RFC 9006 (Benchmarking)"),
    (ipaddress.IPv6Network("2001:3::/32"), "RFC 7450 (Automatic Multicast Tunneling - AMT)"),
    (ipaddress.IPv6Network("2001:4:112::/48"), "RFC 7535 (AS112-v6)"),
    (ipaddress.IPv6Network("2001:10::/28"), "RFC 4843 (Deprecated ORCHID)"),
    (ipaddress.IPv6Network("2001:20::/28"), "RFC 7343 (ORCHIDv2)"),
    (ipaddress.IPv6Network("2001:30::/28"), "RFC 9385 (Drone Remote ID)"),
    (ipaddress.IPv6Network("2001::/23"), "RFC 2928 (IETF Protocol Assignments)"),
    (ipaddress.IPv6Network("2002::/16"), "RFC 3056 / RFC 7526 (6to4 - Deprecated)"),
    (ipaddress.IPv6Network("2620:4f:8000::/48"), "RFC 7534 (Direct Delegation AS112)"),
    (ipaddress.IPv6Network("64:ff9b:1::/48"), "RFC 8215 (Local-Use IPv4/IPv6 Translation)"),
    (ipaddress.IPv6Network("64:ff9b::/96"), "RFC 6052 (IPv4/IPv6 Translation)"),
    (ipaddress.IPv6Network("100::/64"), "RFC 6666 (Discard-Only)"),
    (ipaddress.IPv6Network("3ffe::/16"), "RFC 3701 (6bone - Deprecated / Returned)"),
)

# ASN bogon rules with RFC descriptions
AS_RULES: Tuple[Tuple[int, int, str], ...] = (
    (0, 0, "RFC 6483 / RFC 7607 (Reserved ASN 0)"),
    (23456, 23456, "RFC 6793 (AS_TRANS 4-Byte Transition)"),
    (64496, 64511, "RFC 5398 (Documentation 16-bit)"),
    (64512, 65534, "RFC 1930 / RFC 6996 (Private-Use 16-bit)"),
    (65535, 65535, "RFC 7300 (Reserved 16-bit Last ASN)"),
    (65536, 65551, "RFC 5398 (Documentation 32-bit)"),
    (65552, 131071, "RFC 7249 / IANA (Reserved 32-bit)"),
    (4200000000, 4294967294, "RFC 6996 (Private-Use 32-bit)"),
    (4294967295, 4294967295, "RFC 7300 (Reserved 32-bit Last ASN)"),
)


def parse_asn(asn: Union[int, str]) -> Tuple[int, str]:
    """
    Parses an ASN from int or str (supporting 'AS15169', '15169', '1.0' asdot).
    Returns (asn_int, ""). On error, returns (-1, error_message).
    """
    if isinstance(asn, bool):
        return -1, "ASN must be an integer or string"
    if isinstance(asn, int):
        if asn < 0 or asn > 4294967295:
            return -1, "ASN out of 32-bit range (0-4294967295)"
        return asn, ""

    if isinstance(asn, str):
        s = asn.strip()
        if s.upper().startswith("AS"):
            s = s[2:]
        if not s:
            return -1, "Empty ASN string"
        if "." in s:
            parts = s.split(".")
            if len(parts) != 2:
                return -1, "Invalid asdot syntax"
            try:
                high = int(parts[0])
                low = int(parts[1])
            except ValueError:
                return -1, "Invalid asdot integer values"
            if high < 0 or high > 65535 or low < 0 or low > 65535:
                return -1, "asdot parts out of 16-bit range (0-65535)"
            return (high << 16) | low, ""
        try:
            val = int(s)
        except ValueError:
            return -1, "Invalid ASN syntax"
        if val < 0 or val > 4294967295:
            return -1, "ASN out of 32-bit range (0-4294967295)"
        return val, ""

    return -1, "Invalid ASN type"


def check_asn(asn: Union[int, str]) -> Tuple[bool, str]:
    """
    Checks whether an ASN is valid and publicly routable.
    Accepts int or str (e.g. 15169, 'AS15169', '1.0').
    Returns (True, "") if valid, or (False, reason) if reserved or a bogon.
    """
    num, err = parse_asn(asn)
    if err:
        return False, err

    for start, end, reason in AS_RULES:
        if start <= num <= end:
            return False, reason
    return True, ""


def valid_public_asn(asn: Union[int, str]) -> bool:
    """
    Checks whether an ASN is valid and publicly routable.
    Accepts int or str. Backward-compatible boolean wrapper around check_asn.
    """
    valid, _ = check_asn(asn)
    return valid


def check_ipv4(ip: Union[str, ipaddress.IPv4Address]) -> Tuple[bool, str]:
    """
    Reports whether ip is a publicly routable IPv4 address.
    Returns (True, "") if valid, or (False, reason) if a bogon.
    """
    if isinstance(ip, str):
        try:
            ip = ipaddress.IPv4Address(ip)
        except Exception:
            return False, "Invalid IPv4 address syntax"
    elif not isinstance(ip, ipaddress.IPv4Address):
        return False, "Not an IPv4 address"

    for prefix, reason in V4_BOGON_RULES:
        if ip in prefix:
            return False, reason

    if ip.is_loopback:
        return False, "RFC 1122 (Loopback)"
    if ip.is_link_local:
        return False, "RFC 3927 (Link-Local)"
    if ip.is_multicast:
        return False, "RFC 1112 (Multicast)"
    if not ip.is_global:
        return False, "Not global unicast"

    return True, ""


def check_ipv6(ip: Union[str, ipaddress.IPv6Address]) -> Tuple[bool, str]:
    """
    Reports whether ip is a publicly routable IPv6 address.
    Mapped IPv4-in-IPv6 addresses are unmapped and checked as IPv4.
    Returns (True, "") if valid, or (False, reason) if a bogon.
    """
    if isinstance(ip, str):
        try:
            ip = ipaddress.IPv6Address(ip)
        except Exception:
            return False, "Invalid IPv6 address syntax"
    elif not isinstance(ip, ipaddress.IPv6Address):
        return False, "Not an IPv6 address"

    # IPv4-mapped IPv6 (::ffff:x.x.x.x)
    if ip.ipv4_mapped is not None:
        return check_ipv4(ip.ipv4_mapped)

    for prefix, reason in V6_BOGON_RULES:
        if ip in prefix:
            return False, reason

    if ip.is_loopback:
        return False, "RFC 4291 (Loopback)"
    if ip.is_unspecified:
        return False, "RFC 4291 (Unspecified)"
    if ip.is_link_local:
        return False, "RFC 4291 (Link-Local)"
    if ip.is_private:
        return False, "RFC 4193 (Unique Local Address / ULA)"
    if ip.is_multicast:
        return False, "RFC 4291 (Multicast)"

    # Only 2000::/3 is globally routable
    first_byte = ip.packed[0]
    if first_byte < 0x20 or first_byte > 0x3F:
        return False, "RFC 4291 (IANA Unallocated / Outside 2000::/3 Global Unicast)"

    return True, ""


def check_ip(ip: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, str]:
    """
    Reports whether ip is a publicly routable IP address (IPv4 or IPv6).
    Returns (True, "") if valid, or (False, reason) if invalid or a bogon.
    """
    if isinstance(ip, str):
        try:
            parsed = ipaddress.ip_address(ip)
        except Exception:
            return False, "Invalid IP address syntax"
    elif isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        parsed = ip
    else:
        return False, "Invalid IP address object"

    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped

    if isinstance(parsed, ipaddress.IPv4Address):
        return check_ipv4(parsed)
    return check_ipv6(parsed)


def is_public_ip(ip: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """
    Reports whether ip is a publicly routable IP address.
    Backward-compatible boolean wrapper around check_ip.
    """
    valid, _ = check_ip(ip)
    return valid


def is_public_ipv4(ip: Union[str, ipaddress.IPv4Address]) -> bool:
    """
    Reports whether ip is a publicly routable IPv4 address.
    Backward-compatible boolean wrapper around check_ipv4.
    """
    valid, _ = check_ipv4(ip)
    return valid


def is_public_ipv6(ip: Union[str, ipaddress.IPv6Address]) -> bool:
    """
    Reports whether ip is a publicly routable IPv6 address.
    Backward-compatible boolean wrapper around check_ipv6.
    """
    valid, _ = check_ipv6(ip)
    return valid


def check_prefix(prefix: Union[str, ipaddress.IPv4Network, ipaddress.IPv6Network]) -> Tuple[bool, str]:
    """
    Reports whether prefix sits within publicly routable space.
    Checks whether the network sits inside any bogon subnet, ignoring
    BGP prefix length limits (/8-/24 or /16-/48).
    """
    if isinstance(prefix, str):
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except Exception:
            return False, "Invalid prefix syntax"
    elif isinstance(prefix, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        net = prefix
    else:
        return False, "Invalid prefix object"

    addr = net.network_address
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    if isinstance(addr, ipaddress.IPv4Address):
        return check_ipv4(addr)
    return check_ipv6(addr)


def is_public_prefix(prefix: Union[str, ipaddress.IPv4Network, ipaddress.IPv6Network]) -> bool:
    """
    Reports whether prefix sits within publicly routable space.
    Convenience boolean wrapper around check_prefix.
    """
    valid, _ = check_prefix(prefix)
    return valid


def valid_public_prefix(prefix: Union[str, ipaddress.IPv4Network, ipaddress.IPv6Network]) -> bool:
    """
    Reports whether prefix is a publicly routable, correctly bounded network prefix
    suitable for BGP announcement.
    IPv4: prefix length must be between /8 and /24 (inclusive).
    IPv6: prefix length must be between /16 and /48 (inclusive).
    Prefixes with host bits set (not strict network addresses) are rejected.
    """
    if isinstance(prefix, str):
        try:
            net = ipaddress.ip_network(prefix, strict=True)
        except Exception:
            return False
    elif isinstance(prefix, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        net = prefix
    else:
        return False

    addr = net.network_address
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    if isinstance(addr, ipaddress.IPv4Address):
        if net.prefixlen < 8 or net.prefixlen > 24:
            return False
        return is_public_ipv4(addr)

    # IPv6
    if net.prefixlen < 16 or net.prefixlen > 48:
        return False
    return is_public_ipv6(addr)
