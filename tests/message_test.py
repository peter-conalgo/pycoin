import io
import unittest

from pycoin.block import Block, BlockHeader
from pycoin.message.make_parser_and_packer import (
    make_parser_and_packer, standard_messages, standard_message_post_unpacks, standard_parsing_functions, standard_streamer
)
from pycoin.message.PeerAddress import ip_bin_to_ip4_addr, ip_bin_to_ip6_addr, PeerAddress, IP4_HEADER
from pycoin.message.InvItem import InvItem, ITEM_TYPE_BLOCK, ITEM_TYPE_TX

from pycoin.tx import Tx


def to_bin(obj):
    f = io.BytesIO()
    obj.stream(f)
    return f.getvalue()


def from_bin(cls, blob):
    f = io.BytesIO(blob)
    return cls.parse(f)


class MessageTest(unittest.TestCase):

    def test_make_parser_and_packer(self):
        streamer = standard_streamer(standard_parsing_functions(Block, BlockHeader, Tx))
        btc_parser, btc_packer = make_parser_and_packer(
            streamer, standard_messages(), standard_message_post_unpacks(streamer))
        parser, packer = make_parser_and_packer(streamer, standard_messages(), standard_message_post_unpacks(streamer))
        cases = [("verack", {}), ("ping", dict(nonce=1929)), ("pong", dict(nonce=18373))]
        for msg_name, kwargs in cases:
            data = packer(msg_name, **kwargs)
            v = parser(msg_name, data)
            assert v == kwargs

    def test_ipv6(self):
        self.assertEqual(
            ip_bin_to_ip6_addr(b'&\x07\xf8\xb0@\x06\x08\n\x00\x00\x00\x00\x00\x00 \x0e'),
            "2607:f8b0:4006:80a:0:0:0:200e"
        )

    def test_ipv4(self):
        ip4_bin = b'\xc0\xa8\x01c'
        self.assertEqual(ip_bin_to_ip4_addr(ip4_bin), "192.168.1.99")

    def test_PeerAddress(self):
        pa = PeerAddress(188, IP4_HEADER + b'\xc0\xa8\x01c', 8333)
        pa_bytes = to_bin(pa)
        pa1 = from_bin(PeerAddress, pa_bytes)
        self.assertEqual(pa, pa1)

        pa2 = PeerAddress(188, IP4_HEADER + b'\xc0\xa8\x01b', 8333)
        self.assertTrue(pa1 > pa2)
        self.assertTrue(pa1 >= pa2)
        self.assertTrue(pa2 < pa1)
        self.assertTrue(pa2 <= pa1)
        self.assertNotEqual(pa2, pa1)
        self.assertNotEqual(pa1, pa2)
        self.assertEqual(pa1.host(), "192.168.1.99")
        self.assertEqual(repr(pa1), "192.168.1.99/8333")

        pa_v6 = PeerAddress(945, b'&\x07\xf8\xb0@\x06\x08\n\x00\x00\x00\x00\x00\x00 \x0e', 8333)
        self.assertEqual(pa_v6.host(), "2607:f8b0:4006:80a:0:0:0:200e")

    def test_InvItem(self):
        ii0 = InvItem(ITEM_TYPE_TX, b'\0' * 32)
        ii1 = InvItem(ITEM_TYPE_BLOCK, b'\0' * 32)
        self.assertTrue(ii0 < ii1)
        self.assertTrue(ii1 > ii0)
        self.assertTrue(ii0 <= ii1)
        self.assertTrue(ii1 >= ii0)
        self.assertTrue(ii1 != ii0)
        self.assertFalse(ii1 == ii0)
        self.assertTrue(hash(ii1) != hash(ii0))

        for ii in (ii0, ii1):
            blob = to_bin(ii)
            ii_prime = from_bin(InvItem, blob)
            self.assertEqual(ii, ii_prime)
