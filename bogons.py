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


def is_public_ipv4(ip: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip)
    except:
        return False

    if ip.is_multicast:
        return False

    return ip.is_global


def is_public_ipv6(ip: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip)
    except:
        return False

    if ip.is_multicast:
        return False

    ip_int = int(ip)
    # 6to4 2002::/16
    if ip_int >= 42545680458834377588178886921629466624 and ip_int <= 42550872755692912415807417417958686719:
        return False
    # 6bone 3ffe::/16
    if ip_int >= 85060207136517546210586590865283612672 and ip_int <= 85065399433376081038215121361612832767:
        return False
    # Anything else not in 2000::/3 is not public
    if ip_int > 85070591730234615865843651857942052863:
        return False

    return ip.is_global
