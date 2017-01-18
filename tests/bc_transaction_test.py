#! /usr/bin/env python
# coding=utf-8
"""
Test suite for pycoin library: check validity of txs in files
tx_valid.json and tx_invalid.json. Adapted from Bitcoin Core
transaction_tests.cpp test suite.

The MIT License (MIT)

Copyright (c) 2015 by Marek Miller
Copyright (c) 2015 by Richard Kiss
Copyright (c) 2015 by The Bitcoin Core Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import unittest
import json
import os
import io
import binascii

from pycoin.intbytes import bytes_from_int, byte_to_int
from pycoin.serialize import h2b_rev, h2b
from pycoin.tx import Tx, TxIn, ValidationFailureError
from pycoin.tx.Spendable import Spendable
from pycoin.tx.script.opcodes import OPCODE_TO_INT
from pycoin.tx.script.tools import compile


DEBUG_TX_ID_LIST = []


TX_VALID_JSON = os.path.dirname(__file__) + '/data/tx_valid.json'
TX_INVALID_JSON = os.path.dirname(__file__) + '/data/tx_invalid.json'

from pycoin.tx.script import flags


def parse_flags(flag_string):
    v = 0
    if len(flag_string) > 0:
        for f in flag_string.split(","):
            v |= getattr(flags, "VERIFY_%s" % f)
    return v


def txs_from_json(path):
    """
    Read tests from ./data/tx_??valid.json
    Format is an array of arrays
    Inner arrays are either [ "comment" ]
    or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2], ...], serializedTransaction, verifyFlags]
    ... where all scripts are stringified scripts.

    verifyFlags is a comma separated list of script verification flags to apply, or "NONE"
    """
    comments = None
    with open(path, 'r') as f:
        for tvec in json.load(f):
            if len(tvec) == 1:
                comments = tvec[0]
                continue
            assert len(tvec) == 3
            prevouts = tvec[0]
            for prevout in prevouts:
                assert len(prevout) in (3, 4)

            tx_hex = tvec[1]

            flags = parse_flags(tvec[2])
            try:
                tx = Tx.from_hex(tx_hex)
            except:
                print("Cannot parse tx_hex: %s" % tx_hex)
                raise

            spendable_db = {}
            blank_spendable = Spendable(0, b'', b'\0' * 32, 0)
            for prevout in prevouts:
                coin_value = 1000000
                if len(prevout) == 4:
                    coin_value = prevout[3]
                spendable = Spendable(coin_value=coin_value,
                                      script=compile(prevout[2]),
                                      tx_hash=h2b_rev(prevout[0]), tx_out_index=prevout[1])
                spendable_db[(spendable.tx_hash, spendable.tx_out_index)] = spendable
            unspents = [spendable_db.get((tx_in.previous_hash, tx_in.previous_index), blank_spendable) for tx_in in tx.txs_in]
            tx.set_unspents(unspents)
            yield (tx, flags, comments)


class TestTx(unittest.TestCase):
    pass


def make_f(tx, flags, comments, expect_ok=True):
    tx_hex = tx.as_hex(include_unspents=True)
    def test_f(self):
        why = None
        try:
            tx.check()
        except ValidationFailureError as ex:
            why = str(ex)
        bs = tx.bad_signature_count(flags=flags)
        if bs > 0:
            why = "bad sig count = %d" % bs
        if (why != None) == expect_ok:
            why = why or "tx unexpectedly validated"
            f = open("tx-%s-%x-%s.bin" % (tx.id(), flags, "ok" if expect_ok else "bad"), "wb")
            f.write(tx.as_bin(include_unspents=True))
            f.close()
            self.fail("fail on %s because of %s with hex %s: %s" % (tx.w_id(), why, tx_hex, comments))
    if DEBUG_TX_ID_LIST and tx.w_id() not in DEBUG_TX_ID_LIST:
        return lambda self: 0
    return test_f


def inject():
    for idx, (tx, flags, comments) in enumerate(txs_from_json(TX_VALID_JSON)):
        name_of_f = "test_valid_%02d_%s" % (idx, tx.w_id())
        setattr(TestTx, name_of_f, make_f(tx, flags, comments))
        print("adding %s" % name_of_f)

    for idx, (tx, flags, comments) in enumerate(txs_from_json(TX_INVALID_JSON)):
        name_of_f = "test_invalid_%02d_%s" % (idx, tx.w_id())
        setattr(TestTx, name_of_f, make_f(tx, flags, comments, expect_ok=False))
        print("adding %s" % name_of_f)


inject()





if __name__ == '__main__':
    unittest.main()
