# -*- coding: utf-8 -*-
"""
Extension to support Litecoin


The MIT License (MIT)

Copyright (c) 2013 by Peter D. Gray

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

import binascii
import hashlib
from .encoding import a2b_hashed_base58, EncodingError

def ltc_public_byte_prefix(is_test):
    """LITECOIN Address prefix. Returns b'\30' for main network and b'\x6f' for testnet"""
    # XXX guessing at LTC-testnet value, can't find a reference.
    return b'\x6f' if is_test else b'\x30'

def litecoin_address_to_hash160_sec(litecoin_address, is_test=False):
    """Convert a Litecoin address back to the hash160_sec format of the public key.
    Since we only know the hash of the public key, we can't get the full public key back."""
    blob = a2b_hashed_base58(litecoin_address)
    if len(blob) != 21:
        raise EncodingError("incorrect binary length (%d) for Litecoin address %s" % (len(blob), litecoin_address))
    if blob[:1] != ltc_public_byte_prefix(is_test):
        raise EncodingError("incorrect first byte (%s) for Litecoin address %s" % (blob[0], litecoin_address))
    return blob[1:]

