#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ipaddress
import unittest
import bogons


class BogonsTestCase(unittest.TestCase):
    def test_asn_validation(self):
        # Valid ASNs
        valid_asns = [1, 15169, 13335, 4199999999]
        for asn in valid_asns:
            self.assertTrue(bogons.valid_public_asn(asn), f"ASN {asn} should be valid")
            valid, reason = bogons.check_asn(asn)
            self.assertTrue(valid, f"check_asn({asn}) should be true")
            self.assertEqual(reason, "")

        # Invalid / Reserved ASNs with reasons
        invalid_cases = [
            (0, "RFC 6483 / RFC 7607 (Reserved ASN 0)"),
            (23456, "RFC 6793 (AS_TRANS 4-Byte Transition)"),
            (64496, "RFC 5398 (Documentation 16-bit)"),
            (64511, "RFC 5398 (Documentation 16-bit)"),
            (64512, "RFC 1930 / RFC 6996 (Private-Use 16-bit)"),
            (65534, "RFC 1930 / RFC 6996 (Private-Use 16-bit)"),
            (65535, "RFC 7300 (Reserved 16-bit Last ASN)"),
            (65536, "RFC 5398 (Documentation 32-bit)"),
            (65551, "RFC 5398 (Documentation 32-bit)"),
            (65552, "RFC 7249 / IANA (Reserved 32-bit)"),
            (131071, "RFC 7249 / IANA (Reserved 32-bit)"),
            (4200000000, "RFC 6996 (Private-Use 32-bit)"),
            (4294967294, "RFC 6996 (Private-Use 32-bit)"),
            (4294967295, "RFC 7300 (Reserved 32-bit Last ASN)"),
        ]
        for asn, expected_reason in invalid_cases:
            self.assertFalse(bogons.valid_public_asn(asn), f"ASN {asn} should be invalid")
            valid, reason = bogons.check_asn(asn)
            self.assertFalse(valid, f"check_asn({asn}) should be false")
            self.assertEqual(reason, expected_reason)

        # Valid String ASNs & asdot
        valid_str_asns = ["15169", "AS15169", "as13335", "2.0"]  # 2.0 = 131072 is public 32-bit
        for asn_str in valid_str_asns:
            self.assertTrue(bogons.valid_public_asn(asn_str), f"String ASN {asn_str} should be valid")
            valid, reason = bogons.check_asn(asn_str)
            self.assertTrue(valid, f"check_asn({asn_str}) should be true")
            self.assertEqual(reason, "")

        # Bogon String ASNs & asdot
        bogon_str_cases = [
            ("AS0", "RFC 6483 / RFC 7607 (Reserved ASN 0)"),
            ("as64512", "RFC 1930 / RFC 6996 (Private-Use 16-bit)"),
            ("AS23456", "RFC 6793 (AS_TRANS 4-Byte Transition)"),
            ("1.0", "RFC 5398 (Documentation 32-bit)"),  # 65536
        ]
        for s, expected_reason in bogon_str_cases:
            self.assertFalse(bogons.valid_public_asn(s))
            valid, reason = bogons.check_asn(s)
            self.assertFalse(valid)
            self.assertEqual(reason, expected_reason)

        # ASN Edge Cases & Malformed Inputs
        bad_inputs = [-1, 4294967296, "not-an-asn", "", "AS", "1.2.3", None, True, False, [1]]
        for val in bad_inputs:
            self.assertFalse(bogons.valid_public_asn(val))
            valid, reason = bogons.check_asn(val)
            self.assertFalse(valid)
            self.assertTrue(len(reason) > 0)

    def test_ip_validation(self):
        # Valid Public IPs
        valid_ips = [
            "1.1.1.1",
            "8.8.8.8",
            "11.1.1.1",
            "192.0.1.1",
            "193.168.1.1",
            "2600::",
            "2001:4860:4860::8888",
            "3fff::",
            "::ffff:1.1.1.1",
        ]
        for ip in valid_ips:
            self.assertTrue(bogons.is_public_ip(ip), f"{ip} should be valid public")
            valid, reason = bogons.check_ip(ip)
            self.assertTrue(valid, f"check_ip({ip}) should be true")
            self.assertEqual(reason, "")

        # Bogon IPs with RFC reasons
        bogon_cases = [
            # IPv4
            ("0.0.0.1", "RFC 1122 (This Host on This Network)"),
            ("10.1.2.3", "RFC 1918 (Private-Use)"),
            ("100.64.0.1", "RFC 6598 (Shared Address Space / CGNAT)"),
            ("100.127.255.254", "RFC 6598 (Shared Address Space / CGNAT)"),
            ("127.0.0.1", "RFC 1122 (Loopback)"),
            ("169.254.1.1", "RFC 3927 (Link-Local)"),
            ("172.16.1.1", "RFC 1918 (Private-Use)"),
            ("172.31.255.255", "RFC 1918 (Private-Use)"),
            ("192.0.0.1", "RFC 6333 / RFC 7335 (DS-Lite / Dual-Stack Continuity)"),
            ("192.0.0.50", "RFC 6890 (IETF Protocol Assignments)"),
            ("192.0.0.8", "RFC 7600 (IPv4 Dummy Address)"),
            ("192.0.0.9", "RFC 7725 (PCP Anycast)"),
            ("192.0.0.10", "RFC 8155 (TURN Anycast)"),
            ("192.0.0.170", "RFC 8880 (NAT64/DNS64 Discovery)"),
            ("192.0.2.1", "RFC 5737 (Documentation TEST-NET-1)"),
            ("192.31.196.1", "RFC 7535 (AS112-v4)"),
            ("192.52.193.1", "RFC 7450 (Automatic Multicast Tunneling - AMT)"),
            ("192.88.99.1", "RFC 7526 (6to4 Relay Anycast - Deprecated)"),
            ("192.168.1.1", "RFC 1918 (Private-Use)"),
            ("198.18.1.1", "RFC 2544 (Benchmarking)"),
            ("198.19.255.255", "RFC 2544 (Benchmarking)"),
            ("198.51.100.1", "RFC 5737 (Documentation TEST-NET-2)"),
            ("203.0.113.1", "RFC 5737 (Documentation TEST-NET-3)"),
            ("224.0.0.1", "RFC 1112 (Multicast)"),
            ("240.0.0.1", "RFC 1112 (Reserved / Former Class E)"),
            ("255.255.255.255", "RFC 919 / RFC 8190 (Limited Broadcast)"),

            # IPv6
            ("::", "RFC 4291 (Unspecified)"),
            ("::1", "RFC 4291 (Loopback)"),
            ("fe80::1", "RFC 4291 (Link-Local)"),
            ("fc00::1", "RFC 4193 (Unique Local Address / ULA)"),
            ("fd00::1", "RFC 4193 (Unique Local Address / ULA)"),
            ("ff02::1", "RFC 4291 (Multicast)"),
            ("2001::1", "RFC 4380 (Teredo)"),
            ("2001:1:2::3", "RFC 2928 (IETF Protocol Assignments)"),
            ("2001:2::1", "RFC 5180 / RFC 9006 (Benchmarking)"),
            ("2001:3::1", "RFC 7450 (Automatic Multicast Tunneling - AMT)"),
            ("2001:4:112::1", "RFC 7535 (AS112-v6)"),
            ("2001:10::1", "RFC 4843 (Deprecated ORCHID)"),
            ("2001:20::1", "RFC 7343 (ORCHIDv2)"),
            ("2001:30::1", "RFC 9385 (Drone Remote ID)"),
            ("2001:db8::1", "RFC 3849 (Documentation)"),
            ("2002::1", "RFC 3056 / RFC 7526 (6to4 - Deprecated)"),
            ("2620:4f:8000::1", "RFC 7534 (Direct Delegation AS112)"),
            ("64:ff9b::1", "RFC 6052 (IPv4/IPv6 Translation)"),
            ("64:ff9b:1::1", "RFC 8215 (Local-Use IPv4/IPv6 Translation)"),
            ("100::1", "RFC 6666 (Discard-Only)"),
            ("3ffe::1", "RFC 3701 (6bone - Deprecated / Returned)"),
            ("4000::1", "RFC 4291 (IANA Unallocated / Outside 2000::/3 Global Unicast)"),

            # Mapped Bogon
            ("::ffff:10.0.0.1", "RFC 1918 (Private-Use)"),
        ]
        for ip, expected_reason in bogon_cases:
            self.assertFalse(bogons.is_public_ip(ip), f"{ip} should be bogon")
            valid, reason = bogons.check_ip(ip)
            self.assertFalse(valid, f"check_ip({ip}) should be false")
            self.assertEqual(reason, expected_reason)

        # Malformed IPs
        malformed = ["", "balloon🎈", "11.1.1.1.1", "3fff:::", "not-an-ip", None, 123]
        for s in malformed:
            self.assertFalse(bogons.is_public_ip(s))
            valid, reason = bogons.check_ip(s)
            self.assertFalse(valid)
            self.assertTrue(len(reason) > 0)

    def test_prefix_checking_and_boundaries(self):
        # CheckPrefix: ignores BGP bit boundary filters (/8-/24, /16-/48)
        # /25 public subnet
        valid, reason = bogons.check_prefix("8.8.8.0/25")
        self.assertTrue(valid)
        self.assertEqual(reason, "")
        self.assertTrue(bogons.is_public_prefix("8.8.8.0/25"))

        # /32 public host route
        valid, reason = bogons.check_prefix("1.1.1.1/32")
        self.assertTrue(valid)
        self.assertEqual(reason, "")

        # IPv6 /64 public subnet
        valid, reason = bogons.check_prefix("2600::/64")
        self.assertTrue(valid)
        self.assertEqual(reason, "")

        # /28 private subnet sits in RFC 1918 bogon
        valid, reason = bogons.check_prefix("10.1.2.0/28")
        self.assertFalse(valid)
        self.assertEqual(reason, "RFC 1918 (Private-Use)")

        # ValidPublicPrefix: enforces BGP boundaries and normalized network address
        # IPv4 boundaries
        self.assertTrue(bogons.valid_public_prefix("8.8.8.0/24"))
        self.assertTrue(bogons.valid_public_prefix("8.0.0.0/8"))
        self.assertFalse(bogons.valid_public_prefix("8.0.0.0/7"))   # Too short
        self.assertFalse(bogons.valid_public_prefix("8.8.8.0/25"))  # Too long for BGP
        self.assertFalse(bogons.valid_public_prefix("8.8.8.1/24"))  # Host bits set

        # IPv6 boundaries
        self.assertTrue(bogons.valid_public_prefix("2600::/16"))
        self.assertTrue(bogons.valid_public_prefix("2600::/32"))
        self.assertTrue(bogons.valid_public_prefix("2600::/48"))
        self.assertFalse(bogons.valid_public_prefix("2600::/15"))   # Too short
        self.assertFalse(bogons.valid_public_prefix("2600::/49"))   # Too long for BGP
        self.assertFalse(bogons.valid_public_prefix("2600::1/32"))  # Host bits set
        self.assertFalse(bogons.valid_public_prefix("2001:db8::/32"))  # Documentation bogon

    def test_ip_object_inputs(self):
        # Support passing ipaddress objects directly
        v4_obj = ipaddress.IPv4Address("8.8.8.8")
        self.assertTrue(bogons.is_public_ip(v4_obj))
        self.assertTrue(bogons.is_public_ipv4(v4_obj))

        v6_obj = ipaddress.IPv6Address("2600::")
        self.assertTrue(bogons.is_public_ip(v6_obj))
        self.assertTrue(bogons.is_public_ipv6(v6_obj))

        net_obj = ipaddress.IPv4Network("8.8.8.0/24")
        self.assertTrue(bogons.is_public_prefix(net_obj))
        self.assertTrue(bogons.valid_public_prefix(net_obj))


if __name__ == '__main__':
    unittest.main()
