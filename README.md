# python-bogons

Python version of [github.com/mellowdrifter/bogons](https://github.com/mellowdrifter/bogons).

A lightweight Python library to validate IP address, subnet prefix, and ASN [bogons](https://en.wikipedia.org/wiki/Bogon_filtering) with RFC explanations. Uses only Python's standard library (`ipaddress`).

## Features

- **IP Validation & Reasons**: Test whether an IPv4 or IPv6 address is publicly routable, with exact RFC reason reporting (`check_ip`).
- **Prefix & Subnet Validation**: Check if an IP or subnet falls inside a bogon range (`check_prefix`, ignores BGP announcement length filters) or enforce BGP routing limits (`valid_public_prefix`).
- **ASN Validation & Reasons**: Verify if an Autonomous System Number is public or reserved/private (`check_asn`).
- **RFC Compliant**: Updated with RFC 1122, RFC 1918, RFC 6598, RFC 5737, RFC 7526, RFC 7535, RFC 7450, RFC 7534, RFC 9385, RFC 8880, RFC 7725, RFC 8155, RFC 6483, RFC 7300, etc.
- **Zero Dependencies**: Pure Python standard library (`ipaddress`).

## Installation

```bash
pip install bogons
```

## Usage

### IP Validation with RFC Reasons

```python
import bogons

valid, reason = bogons.check_ip("1.1.1.1")
print(valid, reason)
# Output: True ""

valid, reason = bogons.check_ip("10.0.0.1")
print(valid, reason)
# Output: False "RFC 1918 (Private-Use)"

valid, reason = bogons.check_ip("2001:db8::1")
print(valid, reason)
# Output: False "RFC 3849 (Documentation)"
```

Boolean-only checks remain available:

```python
bogons.is_public_ip("1.1.1.1")     # True
bogons.is_public_ip("10.0.0.1")    # False
bogons.is_public_ip("2600::")      # True
```

### Prefix & Subnet Validation

Use `check_prefix` to determine if a subnet sits within public space (ignoring BGP route boundary filters):

```python
valid, reason = bogons.check_prefix("8.8.8.0/25")
print(valid, reason)
# Output: True ""

valid, reason = bogons.check_prefix("192.168.1.0/24")
print(valid, reason)
# Output: False "RFC 1918 (Private-Use)"
```

To enforce strict BGP announcement length limits (`/8`–`/24` for IPv4, `/16`–`/48` for IPv6) and reject host bits:

```python
bogons.valid_public_prefix("8.8.8.0/24")  # True
bogons.valid_public_prefix("8.8.8.0/25")  # False (too specific for BGP)
bogons.valid_public_prefix("8.8.8.1/24")  # False (host bits set)
```

### ASN Validation with RFC Reasons

```python
valid, reason = bogons.check_asn(15169)
print(valid, reason)
# Output: True ""

valid, reason = bogons.check_asn(64512)
print(valid, reason)
# Output: False "RFC 1930 / RFC 6996 (Private-Use 16-bit)"

# Accepts string with optional "AS" prefix or asdot notation:
valid, reason = bogons.check_asn("AS64512")
# Output: False "RFC 1930 / RFC 6996 (Private-Use 16-bit)"

valid, reason = bogons.check_asn("1.0")
# Output: False "RFC 5398 (Documentation 32-bit)"

bogons.valid_public_asn("AS15169")  # True
bogons.valid_public_asn("AS64512")  # False
```

## License

Apache-2.0