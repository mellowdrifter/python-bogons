#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ipaddress


def valid_public_asn(asn: int) -> bool:

    if not isinstance(asn, int):
        return False

    if asn < 0:
        return False
    # RFC6483, RFC7607
    if asn == 0:
        return False
    # RFC6793
    if asn == 23456:
        return False
    # RFC5398
    if (asn >= 64496) and (asn <= 64511):
        return False
    # RFC1930, RFC6996
    if (asn >= 64512) and (asn <= 65534):
        return False
    # RFC7300
    if asn == 65535:
        return False
    #RFC4893, RFC5398
    if (asn >= 65536) and (asn <= 65551):
        return False
    if (asn >= 65552) and (asn <= 131071):
        return False
    # RFC6996
    if (asn >= 4200000000) and (asn <= 4294967294):
        return False
    # RFC7300
    if asn == 4294967295:
        return False

    # asn should be int < 4200000000
    return asn < 4200000000


def is_public_ip(ip: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip)
    except:
        return False

    if ip.version == 4:
        return is_public_ipv4(ip)
    if ip.version == 6:
        return is_public_ipv6(ip)

    return False


def is_public_ipv4(ip: ipaddress.IPv4Address) -> bool:
    if ip.is_multicast:
        return False

    return ip.is_global


def is_public_ipv6(ip: ipaddress.IPv6Address) -> bool:
    if ip.is_multicast:
        return False
    
    # 6to4 address space
    if ip in ipaddress.IPv6Network('2002::16'):
        return False
    # 6bone address space
    if ip in ipaddress.IPv6Network('3ffe::16'):
        return False
    # Anything else not in 2000::/3 is not public
    if ip not in ipaddress.IPv6Network('2000::/3'):
        return False

    return ip.is_global
