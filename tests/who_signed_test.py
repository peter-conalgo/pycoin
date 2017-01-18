#!/usr/bin/env python

import io
import copy
import unittest
from pycoin.cmds.tx import DEFAULT_VERSION
from pycoin.contrib import who_signed
from pycoin.key import Key
from pycoin.serialize import h2b
from pycoin.tx import Tx, TxIn, TxOut, SIGHASH_ALL, tx_utils
from pycoin.tx.Spendable import Spendable
from pycoin.tx.tx_utils import LazySecretExponentDB
from pycoin.tx.pay_to import ScriptMultisig, ScriptPayToPublicKey, ScriptNulldata
from pycoin.tx.pay_to import build_hash160_lookup, build_p2sh_lookup, script_obj_from_script
from pycoin.tx.script import tools
from pycoin.ui import address_for_pay_to_script, standard_tx_out_script, script_obj_from_address


class ScriptTypesTest(unittest.TestCase):

    def multisig_M_of_N(self, M, N, unsigned_id, signed_id):
        keys = [Key(secret_exponent=i) for i in range(1, N+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        script = ScriptMultisig(m=M, sec_keys=[key.sec() for key in keys[:N]]).script()
        tx_out = TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = tx_utils.create_tx(tx1.tx_outs_as_spendable(), [keys[-1].address()])
        self.assertEqual(tx2.id(), unsigned_id)
        self.assertEqual(tx2.bad_signature_count(), 1)
        hash160_lookup = build_hash160_lookup(key.secret_exponent() for key in keys)
        tx2.sign(hash160_lookup=hash160_lookup)
        self.assertEqual(tx2.id(), signed_id)
        self.assertEqual(tx2.bad_signature_count(), 0)
        self.assertEqual(sorted(who_signed.who_signed_tx(tx2, 0)), sorted(((key.address(), SIGHASH_ALL) for key in keys[:M])))

    def test_create_multisig_1_of_2(self):
        unsigned_id = "dd40f601e801ad87701b04851a4a6852d6b625e481d0fc9c3302faf613a4fc88"
        signed_id = "fb9ccc00d0e30ab2648768104fd777df8f856830233232c5e43f43584aec23d9"
        self.multisig_M_of_N(1, 2, unsigned_id, signed_id)

    def test_create_multisig_2_of_3(self):
        unsigned_id = "6bc5614a41c7c4aa828f5a4314fff23e5e49b1137e5d31e9716eb58f6fb198ff"
        signed_id = "c521962fe9d0e5efb7d0966759c57e7ee2595ce8e05cb342b19265a8722420dd"
        self.multisig_M_of_N(2, 3, unsigned_id, signed_id)

    def test_multisig_one_at_a_time(self):
        M = 3
        N = 3
        keys = [Key(secret_exponent=i) for i in range(1, N+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        script = ScriptMultisig(m=M, sec_keys=[key.sec() for key in keys[:N]]).script()
        tx_out = TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = tx_utils.create_tx(tx1.tx_outs_as_spendable(), [keys[-1].address()])
        ids = ["403e5bfc59e097bb197bf77a692d158dd3a4f7affb4a1fa41072dafe7bec7058",
               "5931d9995e83721243dca24772d7012afcd4378996a8b953c458175f15a544db",
               "9bb4421088190bbbb5b42a9eaa9baed7ec7574a407c25f71992ba56ca43d9c44",
               "03a1dc2a63f93a5cf5a7cb668658eb3fc2eda88c06dc287b85ba3e6aff751771"]
        for i in range(1, N+1):
            self.assertEqual(tx2.bad_signature_count(), 1)
            self.assertEqual(tx2.id(), ids[i-1])
            hash160_lookup = build_hash160_lookup(key.secret_exponent() for key in keys[i-1:i])
            tx2.sign(hash160_lookup=hash160_lookup)
            self.assertEqual(tx2.id(), ids[i])
            self.assertEqual(sorted(who_signed.who_signed_tx(tx2, 0)), sorted(((key.address(), SIGHASH_ALL) for key in keys[:i])))
        self.assertEqual(tx2.bad_signature_count(), 0)

    def test_sign_pay_to_script_multisig(self):
        M, N = 3, 3
        keys = [Key(secret_exponent=i) for i in range(1, N+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        underlying_script = ScriptMultisig(m=M, sec_keys=[key.sec() for key in keys[:N]]).script()
        address = address_for_pay_to_script(underlying_script)
        self.assertEqual(address, "39qEwuwyb2cAX38MFtrNzvq3KV9hSNov3q")
        script = standard_tx_out_script(address)
        tx_out = TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = tx_utils.create_tx(tx1.tx_outs_as_spendable(), [address])
        hash160_lookup = build_hash160_lookup(key.secret_exponent() for key in keys[:N])
        p2sh_lookup = build_p2sh_lookup([underlying_script])
        tx2.sign(hash160_lookup=hash160_lookup, p2sh_lookup=p2sh_lookup)
        self.assertEqual(tx2.bad_signature_count(), 0)
        self.assertRaises(who_signed.NoAddressesForScriptTypeError, who_signed.who_signed_tx, tx2, 0)

if __name__ == "__main__":
    unittest.main()
