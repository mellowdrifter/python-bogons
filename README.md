# python-bogons

Python version of [https://github.com/mellowdrifter/bogons](https://github.com/mellowdrifter/bogons)


Python library to validate IP and ASN [bogons](https://en.wikipedia.org/wiki/Bogon_filtering).
This library does not filter out unassigned space. It will filter IPv4, IPv6, and Autonomous system numbers that have been marked as bogons in the following RFCs:
* [RFC1918](https://tools.ietf.org/html/rfc1918)
* [RFC1930](https://tools.ietf.org/html/rfc1930)
* [RFC4893](https://tools.ietf.org/html/rfc4893)
* [RFC5398](https://tools.ietf.org/html/rfc5398)
* [RFC6483](https://tools.ietf.org/html/rfc6483)
* [RFC6793](https://tools.ietf.org/html/rfc6793)
* [RFC6996](https://tools.ietf.org/html/rfc6996)
* [RFC7300](https://tools.ietf.org/html/rfc7300)
* [RFC7607](https://tools.ietf.org/html/rfc7607)

For IPv6: 6to4, 6bone, and any prefix not in 2000::/3 is marked as invalid.


# Install
```pip install bogons```

# How to use
```
import bogons
>>> bogons.is_public_ip("1.1.1.1")
True
>>> bogons.is_public_ip("10.0.0.0")
False
>>> bogons.is_public_ip("2600::")
True
>>> bogons.is_public_ip("4600::")
False
>>> bogons.valid_public_asn(1)
True
>>> bogons.valid_public_asn(23456)
False
```

# Development
I welcome pull requests for updated RFCs or errors.