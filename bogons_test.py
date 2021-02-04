import bogons
import unittest


class ValidPublicASNTest(unittest.TestCase):
    def test(self):
        self.assertEqual(bogons.ValidPublicASN(-1), False)
        self.assertEqual(bogons.ValidPublicASN(0), False)
        self.assertEqual(bogons.ValidPublicASN(1), True)
        self.assertEqual(bogons.ValidPublicASN(23456), False)
        self.assertEqual(bogons.ValidPublicASN(64496), False)
        self.assertEqual(bogons.ValidPublicASN(64511), False)
        self.assertEqual(bogons.ValidPublicASN(64512), False)
        self.assertEqual(bogons.ValidPublicASN(65534), False)
        self.assertEqual(bogons.ValidPublicASN(65535), False)
        self.assertEqual(bogons.ValidPublicASN(65551), False)
        self.assertEqual(bogons.ValidPublicASN(131071), False)
        self.assertEqual(bogons.ValidPublicASN(4199999999), True)
        self.assertEqual(bogons.ValidPublicASN(4200000000), False)
        self.assertEqual(bogons.ValidPublicASN(4294967295), False)
        self.assertEqual(bogons.ValidPublicASN(18446744073709551615), False)
        self.assertEqual(bogons.ValidPublicASN("word"), False)
