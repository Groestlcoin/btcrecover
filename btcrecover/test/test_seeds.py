#!/usr/bin/env python
# -*- coding: utf-8 -*-

# test_seeds.py -- unit tests for seedrecover.py
# Copyright (C) 2014-2017 Christopher Gurnee
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4
#
#                      Thank You!


import warnings, unittest, os, tempfile, shutil, filecmp, sys, hashlib, random, mmap, pickle
if __name__ == '__main__':
    sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))
from btcrecover import btcrseed, btcrpass
from btcrecover.addressset import AddressSet

wallet_dir = os.path.join(os.path.dirname(__file__), "test-wallets")


def setUpModule():
    global orig_warnings
    orig_warnings = warnings.catch_warnings()
    orig_warnings.__enter__()  # save the current warnings settings (it's a context manager)
    # Convert warnings to errors:
    warnings.simplefilter("error")

def tearDownModule():
    orig_warnings.__exit__(None, None, None)  # restore the original warnings settings


class TestRecoveryFromWallet(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        btcrseed.register_autodetecting_wallets()

    # Checks a test wallet against the known mnemonic, and ensures
    # that the library doesn't make any changes to the wallet file
    def wallet_tester(self, wallet_basename, correct_mnemonic, **kwds):
        assert os.path.basename(wallet_basename) == wallet_basename
        wallet_filename = os.path.join(wallet_dir, wallet_basename)

        temp_dir = tempfile.mkdtemp("-test-btcr")
        try:
            temp_wallet_filename = os.path.join(temp_dir, wallet_basename)
            shutil.copyfile(wallet_filename, temp_wallet_filename)

            wallet = btcrseed.btcrpass.load_wallet(temp_wallet_filename)

            # Convert the mnemonic string into a mnemonic_ids_guess
            wallet.config_mnemonic(correct_mnemonic, **kwds)
            correct_mnemonic = btcrseed.mnemonic_ids_guess

            # Creates wrong mnemonic id guesses
            wrong_mnemonic_iter = wallet.performance_iterator()

            self.assertEqual(wallet.return_verified_password_or_false(
                (wrong_mnemonic_iter.__next__(), wrong_mnemonic_iter.__next__())), (False, 2))
            self.assertEqual(wallet.return_verified_password_or_false(
                (wrong_mnemonic_iter.__next__(), correct_mnemonic, wrong_mnemonic_iter.__next__())), (correct_mnemonic, 2))

            del wallet
            self.assertTrue(filecmp.cmp(wallet_filename, temp_wallet_filename, False))  # False == always compare file contents
        finally:
            shutil.rmtree(temp_dir)

    def test_electrum1_legacy(self):
        self.wallet_tester("electrum-wallet", "straight subject wild ask clean possible age hurt squeeze cost stuck softly")

    def test_electrum2_legacy(self):
        self.wallet_tester("electrum2-wallet", "eagle pair eager human cage forget pony fall robot vague later bright acid",
            expected_len=13)

    def test_electrum27_legacy(self):
        self.wallet_tester("electrum27-wallet", "spot deputy pencil nasty fire boss moral rubber bacon thumb thumb icon",
            expected_len=12)

    def test_electrum2_upgradedfrom_electrum1_legacy(self):
        self.wallet_tester("electrum1-upgradedto-electrum2-wallet", "straight subject wild ask clean possible age hurt squeeze cost stuck softly")

    def test_electrum27_upgradedfrom_electrum1_legacy(self):
        self.wallet_tester("electrum1-upgradedto-electrum27-wallet", "straight subject wild ask clean possible age hurt squeeze cost stuck softly")

class TestRecoveryFromMPK(unittest.TestCase):

    def mpk_tester(self, wallet_type, the_mpk, correct_mnemonic, test_path = None, **kwds):

        #Don't call the wallet create with a path parameter if we don't have to. (for the same of compatibility across wallet types)
        if test_path == None:
            wallet = wallet_type.create_from_params(mpk=the_mpk)
        else:
            wallet = wallet_type.create_from_params(mpk=the_mpk, path=test_path)

        # Convert the mnemonic string into a mnemonic_ids_guessde
        wallet.config_mnemonic(correct_mnemonic, **kwds)
        correct_mnemonic = btcrseed.mnemonic_ids_guess

        # Creates wrong mnemonic id guesses
        wrong_mnemonic_iter = wallet.performance_iterator()

        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.__next__(), wrong_mnemonic_iter.__next__())), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.__next__(), correct_mnemonic, wrong_mnemonic_iter.__next__())), (correct_mnemonic, 2))

    def test_electrum1_xpub_legacy(self):
        self.mpk_tester(btcrseed.WalletElectrum1,
            "c79b02697b32d9af63f7d2bd882f4c8198d04f0e4dfc5c232ca0c18a87ccc64ae8829404fdc48eec7111b99bda72a7196f9eb8eb42e92514a758f5122b6b5fea",
            "straight subject wild ask clean possible age hurt squeeze cost stuck softly")

    def test_electrum2_xpub_legacy(self):
        self.mpk_tester(btcrseed.WalletElectrum2,
            "xpub661MyMwAqRbcGsUXkGBkytQkYZ6M16bFWwTocQDdPSm6eJ1wUsxG5qty1kTCUq7EztwMscUstHVo1XCJMxWyLn4PP1asLjt4gPt3HkA81qe",
            "eagle pair eager human cage forget pony fall robot vague later bright acid",
            expected_len=13)

    def test_electrum27_xpub_legacy(self):
        self.mpk_tester(btcrseed.WalletElectrum2,
            "xpub661MyMwAqRbcGt6qtQ19Ttwvo5Dbf2cQdA2GMf9Xkjth8NqYXXordg3gLK1npATRm9Fr7d7fA5ziCwqEVMmzeRezofp8CEaru8pJ57zV8hN",
            "spot deputy pencil nasty fire boss moral rubber bacon thumb thumb icon",
            expected_len=12)

    def test_electrum2_xpub_legacy_ja(self):
        self.mpk_tester(btcrseed.WalletElectrum2,
            "xpub661MyMwAqRbcFAyy6MaWCK5uGHhgvMZNaFbKy1TbSrcEm8oCgD3N2AfzPC8ndmdvcQbY8EbU414X4xNrs9dcNgcntShiBFJYJ6HJy7zKnQV",
            u"すんぽう うけつけ ぬいくぎ きどう ごはん たかね いてざ よしゅう なにもの われる たんき さとる あじわう",
            expected_len=13)

    TEST_ELECTRUM2_PASS_XPUB = "xpub661MyMwAqRbcG4s8buUEpDeeBMZeXxnroY3i9jZJNQuDrWQaCyR5Mvk9pmRK5q5WrEKTwSuYwBiSjcp3ZkM2ujhngFQXxvrTyv2uFCryyii"
    def test_electrum2_xpub_pass_legacy(self):
        self.mpk_tester(btcrseed.WalletElectrum2,
            self.TEST_ELECTRUM2_PASS_XPUB,
            "eagle pair eager human cage forget pony fall robot vague later bright acid",
            expected_len=13, passphrase=u"btcr test password 测试密码")

    def test_electrum2_xpub_pass_normalize_legacy(self):
        p = u" btcr  TEST  ℙáⓢⓢᵂöṝⅆ  测试  密码 "
        assert p == u" btcr  TEST  \u2119\xe1\u24e2\u24e2\u1d42\xf6\u1e5d\u2146  \u6d4b\u8bd5  \u5bc6\u7801 "
        self.mpk_tester(btcrseed.WalletElectrum2,
            self.TEST_ELECTRUM2_PASS_XPUB,
            "eagle pair eager human cage forget pony fall robot vague later bright acid",
            expected_len=13, passphrase=p)

    def test_electrum2_xpub_pass_wide_legacy(self):
        p = u"𝔅tcr 𝔗est 𝔓assword 测试密码"
        assert p == u"\U0001d505tcr \U0001d517est \U0001d513assword \u6d4b\u8bd5\u5bc6\u7801"
        self.mpk_tester(btcrseed.WalletElectrum2,
            # for narrow Unicode builds, check that we reproduce the same Electrum 2.x bugs:
            "xpub661MyMwAqRbcGYwDPmhGppsmr2NxcoFNAzGy3qRcE9wrtQhF6tCjtitFnizWKHv684AfshexRAiByRFX3VHpugBcAMYpwQezeYroi53KEKM"
                if sys.maxunicode < 65536 else
            # for wide Unicode builds, there are no bugs:
            self.TEST_ELECTRUM2_PASS_XPUB,
            "eagle pair eager human cage forget pony fall robot vague later bright acid",
            expected_len=13, passphrase=p)

    def test_bitcoinj_xpub_legacy(self):
        # an xpub at path m/0', as Bitcoin Wallet for Android/BlackBerry would export
        self.mpk_tester(btcrseed.WalletBitcoinj,
            "xpub67tjk7ug7iNivs1f1pmDswDDbk6kRCe4U1AXSiYLbtp6a2GaodSUovt3kNrDJ2q18TBX65aJZ7VqRBpnVJsaVQaBY2SANYw6kgZf4QLCpPu",
            "laundry foil reform disagree cotton hope loud mix wheel snow real board")

    def test_bip39_xpub(self):
        # an xpub at path m/44'/0'/0', as any native segwit BIP39 wallet would export
        self.mpk_tester(btcrseed.WalletBIP39,
            "xpub6BgCDhMefYxRS1gbVbxyokYzQji65v1eGJXGEiGdoobvFBShcNeJt97zoJBkNtbASLyTPYXJHRvkb3ahxaVVGEtC1AD4LyuBXULZcfCjBZx",
            "certain come keen collect slab gauge photo inside mechanic deny leader drop")

    def test_bip39_ypub(self):
        # an ypub at path m/49'/0'/0', as any native segwit BIP39 wallet would export
        self.mpk_tester(btcrseed.WalletBIP39,
            "ypub6X4G7a9RYWheXmmhfrMR8Nt5XeThiupghvdiYyZFsRWUKKSfzamAUM66Ay9P8XsD7asG6PqSBBDbGihKQndHfgkg2HnHfx2fN69AYzpcxVT",
            "ice stool great wine enough odor vocal crane owner magnet absent scare",
            "m/49'/0'/0'/0")

    def test_bip39_zpub(self):
        # an zpub at path m/84'/0'/0', as any native segwit BIP39 wallet would export
        self.mpk_tester(btcrseed.WalletBIP39,
            "zpub6rpXnwsvpxao28enE4M3xMbHuEkMfhqQc3o1uXp8pBYUA7wG2Ez4SBDFJCWJr3vaP2ysauHX6f68iWzVBzWMkc4BBz9DhFZ9MpKVZHGBLKo",
            "ice stool great wine enough odor vocal crane owner magnet absent scare",
            "m/84'/0'/0'/0")

    def test_bip44_firstfour(self):
        # an xpub at path m/44'/0'/0', as Mycelium for Android would export
        self.mpk_tester(btcrseed.WalletBIP39,
            "xpub6BgCDhMefYxRS1gbVbxyokYzQji65v1eGJXGEiGdoobvFBShcNeJt97zoJBkNtbASLyTPYXJHRvkb3ahxaVVGEtC1AD4LyuBXULZcfCjBZx",
            "cert come keen coll slab gaug phot insi mech deny lead drop")

    def test_bip44_ja(self):
        # an xpub at path m/44'/0'/0'
        self.mpk_tester(btcrseed.WalletBIP39,
            "xpub6BfYc7HCQuKNxRMfmUhtkJ8HQ5A4t4zTy8cAQWjD7x5SZAdUD2QM2WoymmGfAD84mgbXbxyWiR922dyRtZUK2JPtBr8YLTzcQod3orvGB3k",
            u"あんまり　おんがく　いとこ　ひくい　こくはく　あらゆる　てあし　げどく　はしる　げどく　そぼろ　はみがき")

    def test_bip44_pass(self):
        # an xpub at path m/44'/0'/0', as Mycelium for Android would export
        self.mpk_tester(btcrseed.WalletBIP39,
            "xpub6D3uXJmdUg4xVnCUkNXJPCkk18gZAB8exGdQeb2rDwC5UJtraHHARSCc2Nz7rQ14godicjXiKxhUn39gbAw6Xb5eWb5srcbkhqPgAqoTMEY",
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",
            passphrase=u"btcr-test-password")

    def test_bip44_pass_unicode(self):
        # an xpub at path m/44'/0'/0', as Mycelium for Android would export
        self.mpk_tester(btcrseed.WalletBIP39,
            "xpub6CZe1G1A1CaaSepbekLMSk1sBRNA9kHZzEQCedudHAQHHB21FW9fYpQWXBevrLVQfL8JFQVFWEw3aACdr6szksaGsLiHDKyRd1rPJ6ev5ig",
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",
            passphrase=u"btcr-тест-пароль")


is_sha3_loadable = None
def can_load_keccak():
    global is_sha3_loadable
    if is_sha3_loadable is None:
        try:
            from eth_hash.auto import keccak
            keccak(b'')
            is_sha3_loadable = True
        except ImportError:
            is_sha3_loadable = False
    return is_sha3_loadable


class TestRecoveryFromAddress(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            hashlib.new("ripemd160")
        except ValueError:
            raise unittest.SkipTest("requires that hashlib implements RIPEMD-160")

    def address_tester(self, wallet_type, the_address, the_address_limit, correct_mnemonic, test_path = None, pathlist_file = None, **kwds):
        assert the_address_limit > 1

        if pathlist_file:
            test_path = btcrseed.load_pathlist("./common-derivation-pathlists/" + pathlist_file)

        #Don't call the wallet create with a path parameter if we don't have to. (for the same of compatibility across wallet types)
        if test_path == None:
            wallet = wallet_type.create_from_params(addresses=[the_address], address_limit=the_address_limit)
        else:
            wallet = wallet_type.create_from_params(addresses=[the_address], address_limit=the_address_limit, path=test_path)

        # Convert the mnemonic string into a mnemonic_ids_guess
        wallet.config_mnemonic(correct_mnemonic, **kwds)
        correct_mnemonic_ids = btcrseed.mnemonic_ids_guess

        # Creates wrong mnemonic id guesses
        wrong_mnemonic_iter = wallet.performance_iterator()

        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.__next__(), wrong_mnemonic_iter.__next__())), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.__next__(), correct_mnemonic_ids, wrong_mnemonic_iter.__next__())), (correct_mnemonic_ids, 2))

        # Make sure the address_limit is respected (note the "the_address_limit-1" below)
        wallet = wallet_type.create_from_params(addresses=[the_address], address_limit=the_address_limit-1)
        wallet.config_mnemonic(correct_mnemonic, **kwds)
        self.assertEqual(wallet.return_verified_password_or_false(
            (correct_mnemonic_ids,)), (False, 1))

    def test_electrum1_addr_legacy_BTC(self):
        self.address_tester(btcrseed.WalletElectrum1, "12zAz6pAB6LhzGSZFCc6g9uBSWzwESEsPT", 3,
            "straight subject wild ask clean possible age hurt squeeze cost stuck softly")

    def test_electrum2_addr_legacy_BTC(self):
        self.address_tester(btcrseed.WalletElectrum2, "14dpd9nayyoyCTNki5UUsm1KnAZ1x7o83E", 5,
            "eagle pair eager human cage forget pony fall robot vague later bright acid",
            expected_len=13)

    def test_electrum27_addr_legacy_BTC(self):
        self.address_tester(btcrseed.WalletElectrum2, "1HQrNUBEsEqwEaZZzMqqLqCHSVCGF7dTVS", 5,
            "spot deputy pencil nasty fire boss moral rubber bacon thumb thumb icon",
            expected_len=12)

    def test_electrum27_addr_legacy_LTC(self):
        self.address_tester(btcrseed.WalletElectrum2, "LcgWmmHWX3FdysFCFaNGDTywQBcCepvrQ8", 5,
            "fiber bubble warm green banana blood program ship barrel tennis cigar song",
            expected_len=12)

    def test_electrum27_addr_segwit_BTC(self):
        self.address_tester(btcrseed.WalletElectrum2, "bc1qztc99re7ml7hv4q4ds3jv29w7u4evwqd6t76kz", 5,
                            "first focus motor give search custom grocery suspect myth popular trigger praise",
                            expected_len=12)

    def test_electrum27_addr_segwit_LTC(self):
            self.address_tester(btcrseed.WalletElectrum2, "ltc1qk3rqeum7p9xn8kcr0hx8mapr8mgc5exx7fypeh", 5,
                            "reduce cactus invite ask athlete address area earth place price rural usual",
                            expected_len=12)

    def test_electrum27_electroncash_cashaddr_BCH(self):

        self.address_tester(btcrseed.WalletElectrum2, "bitcoincash:qqvnr88mcqff3uzyjgc2e87ncwpsjth9yyyqmhq457", 5,
            "huge rifle suffer segment ankle negative turkey inhale notable bullet forest run",
            expected_len=12)

    def test_bitcoinj_addr_legacy_BTC(self):

        self.address_tester(btcrseed.WalletBitcoinj, "17Czu38CcLwWr8jFZrDJBHWiEDd2QWhPSU", 4,
            "skin join dog sponsor camera puppy ritual diagram arrow poverty boy elbow")

    def test_bip44_addr_BTC_defaultderivationpaths(self):
        self.address_tester(btcrseed.WalletBIP39, "1AiAYaVJ7SCkDeNqgFz7UDecycgzb6LoT3", 2,
                            "certain come keen collect slab gauge photo inside mechanic deny leader drop",)

    def test_bip49_addr_BTC_defaultderivationpaths(self):
        self.address_tester(btcrseed.WalletBIP39, "3NiRFNztVLMZF21gx6eE1nL3Q57GMGuunG", 2,
                            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby")

    def test_bip84_addr_BTC_defaultderivationpaths(self):
        self.address_tester(btcrseed.WalletBIP39, "bc1qv87qf7prhjf2ld8vgm7l0mj59jggm6ae5jdkx2", 2,
                            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby")

    def test_bip44_addr_BTC(self):
        self.address_tester(btcrseed.WalletBIP39, "1AiAYaVJ7SCkDeNqgFz7UDecycgzb6LoT3", 2,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop", "m/44'/0'/0'/0")

    def test_bip44_addr_BTC_multi_coin_derivationpaths(self):
        self.address_tester(btcrseed.WalletBIP39, "1AiAYaVJ7SCkDeNqgFz7UDecycgzb6LoT3", 2,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop", "m/44'/4'/0'/0,m/44'/3'/0'/0,m/44'/2'/0'/0,m/44'/1'/0'/0,m/44'/0'/0'/0")

    def test_bip44_addr_BTC_multi_account_derivationpaths(self):
        self.address_tester(btcrseed.WalletBIP39, "1Bi4fRZTPna1nbBJ8KLxaFfWV3BFDV9xj3", 2,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop", "m/44'/0'/0'/0,m/44'/0'/1'/0,m/44'/0'/2'/0,m/44'/0'/3'/0,m/44'/0'/4'/0")

    def test_bip49_addr_BTC(self):
        self.address_tester(btcrseed.WalletBIP39, "3NiRFNztVLMZF21gx6eE1nL3Q57GMGuunG", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/49'/0'/0'/0")
            
    def test_bip84_addr_BTC(self):
        self.address_tester(btcrseed.WalletBIP39, "bc1qv87qf7prhjf2ld8vgm7l0mj59jggm6ae5jdkx2", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/84'/0'/0'/0")
            
    def test_bip44_addr_LTC(self):
        self.address_tester(btcrseed.WalletBIP39, "LhHbcBk84JpB41otvD7qqWzyGgyr8yDJ2a", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/2'/0'/0")
            
    def test_bip49_addr_LTC(self):
        self.address_tester(btcrseed.WalletBIP39, "MQT8szKNYyJU1hUPLnsfCYXkqLQbTewsj9", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/49'/2'/0'/0")
            
    def test_bip84_addr_LTC(self):
        self.address_tester(btcrseed.WalletBIP39, "ltc1qeyk3wpf2zjqh8h6zz722tfrf4asq0st2mc05ed", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/84'/2'/0'/0")
            
    def test_bip44_addr_VTC(self):
        self.address_tester(btcrseed.WalletBIP39, "VwrYFHeKbneYZdkPWTpXsUs3ZQ4ERan9tG", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/28'/0'/0")
            
    def test_bip49_addr_VTC(self):
        self.address_tester(btcrseed.WalletBIP39, "33DUUsVoodofnbrxFhqCSBkKaqjCHzQyYU", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/49'/28'/0'/0")
            
    def test_bip84_addr_VTC(self):
        self.address_tester(btcrseed.WalletBIP39, "vtc1q4r6d6w0xnd4t2rlj8njcl7m7a9k0ezk9rjnc77", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/84'/28'/0'/0")
            
    def test_bip44_addr_MONA(self):
        self.address_tester(btcrseed.WalletBIP39, "MHKtawgixN8ZKgae3ZxRuwd3ueKZy573By", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/22'/0'/0")
            
    def test_bip49_addr_MONA(self):
        self.address_tester(btcrseed.WalletBIP39, "P8gv2vrMyVhDdjHgJf6yxH3vGarM9fCZ9f", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/49'/22'/0'/0")
            
    def test_bip84_addr_MONA(self):
        self.address_tester(btcrseed.WalletBIP39, "monacoin1q9v93ngm8srxtq7lwzypehax7xvewh2vch68m2f", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/84'/22'/0'/0")

    def test_bip44_addr_DGB(self):
        self.address_tester(btcrseed.WalletBIP39, "D8uui9mGXztcpZy5t5jWpSimCCyEDjYRHY", 5,
                            "barrel tag debate reopen federal fee soda fog twelve garage sweet current",
                            "m/44'/20'/0'/0")

    def test_bip49_addr_DGB(self):
        self.address_tester(btcrseed.WalletBIP39, "SjM4p9vWB7GvsiNMgyZef67SJz3SgmPwhj", 5,
                            "barrel tag debate reopen federal fee soda fog twelve garage sweet current",
                            "m/49'/20'/0'/0")

    def test_bip84_addr_DGB(self):
        self.address_tester(btcrseed.WalletBIP39, "dgb1qmtpcmpt5amuvvwvpelh220ec2ck7q4prsy2tqy", 5,
                            "barrel tag debate reopen federal fee soda fog twelve garage sweet current",
                            "m/84'/20'/0'/0")

    def test_bip44_addr_BCH_CashAddr(self):
        self.address_tester(btcrseed.WalletBIP39, "bitcoincash:qrdupm96x04u3ssjnuj7lpy7adt9y34p5vzh95y0y7", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/145'/0'/0")

    def test_bip44_addr_BCH_CashAddr_NoPrefix(self):
        self.address_tester(btcrseed.WalletBIP39, "qrdupm96x04u3ssjnuj7lpy7adt9y34p5vzh95y0y7", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/145'/0'/0")

    def test_bip44_addr_DASH(self):
        self.address_tester(btcrseed.WalletBIP39, "XkRVBsXz1UG7LP48QKT4ZEbyUS54oRjYpM", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/5'/0'/0")

    def test_bip44_addr_DOGE(self):
        self.address_tester(btcrseed.WalletBIP39, "DANb1e9B2WtHJNDJUsiu1fTrtAzGJhqkPa", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/3'/0'/0")

    def test_bip44_addr_GRS(self):
        self.address_tester(btcrseed.WalletBIP39, "FWoJyPj8sFzBN1dVdLfG8ozrVLRjwZaC78", 2,
            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/17'/0'/0")

    @unittest.skipUnless(can_load_keccak(), "requires pycryptodome")
    def test_ethereum_addr(self):
        self.address_tester(btcrseed.WalletEthereum, "0x9544a5BD7D9AACDc0A12c360C1ec6182C84bab11", 3,
            "cable top mango offer mule air lounge refuse stove text cattle opera")

    # tests for a bug affecting certain seeds/wallets in v0.7.1
    @unittest.skipUnless(can_load_keccak(), "requires pycryptodome")
    def test_ethereum_addr_padding_bug(self):
        self.address_tester(btcrseed.WalletEthereum, "0xaeaa91ba7235dc2d90e28875d3e466aaa27e076d", 2,
            "appear section card oak mercy output person grab rotate sort where rural")

    # Test to ensure that bundled derivation path files work correctly
    def test_pathfile_BTC_Electrum_Legacy(self):
        self.address_tester(btcrseed.WalletElectrum2, "LcgWmmHWX3FdysFCFaNGDTywQBcCepvrQ8", 5,
            "fiber bubble warm green banana blood program ship barrel tennis cigar song",
            pathlist_file="Electrum.txt",
            expected_len=12)

    def test_pathfile_BTC_Electrum_Segwit(self):
        self.address_tester(btcrseed.WalletElectrum2, "bc1qztc99re7ml7hv4q4ds3jv29w7u4evwqd6t76kz", 5,
                            "first focus motor give search custom grocery suspect myth popular trigger praise",
                            pathlist_file="Electrum.txt",
                            expected_len=12)

    def test_pathfile_BTC_BRD(self):
        self.address_tester(btcrseed.WalletBIP39, "1FpWokPArYJKkWWiTqsnoVaFJL4PM3Nqdf", 2,
                            "talk swamp tool right wide vital midnight cushion fiber blouse field transfer",
                            pathlist_file="BTC.txt")

    def test_pathfile_BTC_BIP44(self):
        self.address_tester(btcrseed.WalletBIP39, "1AiAYaVJ7SCkDeNqgFz7UDecycgzb6LoT3", 2,
                            "certain come keen collect slab gauge photo inside mechanic deny leader drop",
                            pathlist_file="BTC.txt")

    def test_pathfile_BTC_BIP49(self):
        self.address_tester(btcrseed.WalletBIP39, "3NiRFNztVLMZF21gx6eE1nL3Q57GMGuunG", 2,
                            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby",
                            pathlist_file="BTC.txt")

    def test_pathfile_BTC_BIP84(self):
        self.address_tester(btcrseed.WalletBIP39, "bc1qv87qf7prhjf2ld8vgm7l0mj59jggm6ae5jdkx2", 2,
                            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby",
                            pathlist_file="BTC.txt")

    def test_pathfile_LTC_BIP44(self):
        self.address_tester(btcrseed.WalletBIP39, "LhHbcBk84JpB41otvD7qqWzyGgyr8yDJ2a", 2,
                            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby",
                            pathlist_file="LTC.txt")

    def test_pathfile_LTC_Atomic(self):
        self.address_tester(btcrseed.WalletBIP39, "LZzJsDgidaRQXicyd5Rb2LbRZd5SR6QqrS", 2,
                            "keen term crouch physical together vital oak predict royal quantum tomorrow chunk",
                            pathlist_file="LTC.txt")

    def test_pathfile_LTC_BIP49(self):
        self.address_tester(btcrseed.WalletBIP39, "MQT8szKNYyJU1hUPLnsfCYXkqLQbTewsj9", 2,
                            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby",
                            pathlist_file="LTC.txt")

    def test_pathfile_LTC_BIP84(self):
        self.address_tester(btcrseed.WalletBIP39, "ltc1qeyk3wpf2zjqh8h6zz722tfrf4asq0st2mc05ed", 2,
                            "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby",
                            pathlist_file="LTC.txt")

    @unittest.skipUnless(can_load_keccak(), "requires pycryptodome")
    def test_pathfile_Eth_Coinomi(self):
        self.address_tester(btcrseed.WalletEthereum, "0xE16fCCbBa5EC2C2e4584A846ce3b77a6F37E863c", 2,
                            "talk swamp tool right wide vital midnight cushion fiber blouse field transfer",
                            pathlist_file="ETH.txt")
    @unittest.skipUnless(can_load_keccak(), "requires pycryptodome")
    def test_pathfile_Eth_Default(self):
        self.address_tester(btcrseed.WalletEthereum, "0x1a05a75E4041eFB46A34F208b677F82C079197D8", 2,
                            "talk swamp tool right wide vital midnight cushion fiber blouse field transfer",
                            pathlist_file="ETH.txt")

    def test_pathfile_BCH_Unsplit(self):
        self.address_tester(btcrseed.WalletBIP39, "1AiAYaVJ7SCkDeNqgFz7UDecycgzb6LoT3", 2,
                            "certain come keen collect slab gauge photo inside mechanic deny leader drop",
                            pathlist_file="BCH.txt")

    def test_pathfile_BCH(self):
        self.address_tester(btcrseed.WalletBIP39, "bitcoincash:qz7753xzek843j50cgtc526wdmlpm5v5eyt92gznrt", 2,
                            "certain come keen collect slab gauge photo inside mechanic deny leader drop",
                            pathlist_file="BCH.txt")

class TestAddressSet(unittest.TestCase):
    HASH_BYTES     = 1
    TABLE_LEN      = 2 ** (8*HASH_BYTES)
    BYTES_PER_ADDR = AddressSet(1)._bytes_per_addr

    def test_add(self):
        aset = AddressSet(self.TABLE_LEN)
        addr = "".join(chr(b) for b in range(20))
        self.assertNotIn(addr, aset)
        aset.add(addr)
        self.assertIn   (addr, aset)
        self.assertEqual(len(aset), 1)

    def collision_tester(self, aset, addr1, addr2):
        aset.add(addr1)
        self.assertIn   (addr1, aset)
        self.assertNotIn(addr2, aset)
        self.assertEqual(len(aset), 1)
        aset.add(addr2)
        self.assertIn   (addr1, aset)
        self.assertIn   (addr2, aset)
        self.assertEqual(len(aset), 2)
        return aset
    #
    def test_collision(self):
        aset  = AddressSet(self.TABLE_LEN)
        # the last HASH_BYTES (1) bytes are the "hash", and only the next BYTES_PER_ADDR (8) rightmost bytes are stored
        addr1 = "".join(chr(b) for b in range(20))
        addr2 = addr1.replace(chr(20 - self.HASH_BYTES - self.BYTES_PER_ADDR), "\0")  # the leftmost byte that's stored
        self.collision_tester(aset, addr1, addr2)
    #
    def test_collision_fail(self):
        aset  = AddressSet(self.TABLE_LEN)
        # the last 1 (HASH_BYTES) bytes are the "hash", and only the next 8 (BYTES_PER_ADDR) rightmost bytes are stored
        addr1 = "".join(chr(b) for b in range(20))
        addr2 = addr1.replace(chr(20 - self.HASH_BYTES - self.BYTES_PER_ADDR - 1), "\0")  # the rightmost byte not stored
        self.assertRaises(unittest.TestCase.failureException, self.collision_tester, aset, addr1, addr2)
        self.assertEqual(len(aset), 1)

    def test_null(self):
        aset = AddressSet(self.TABLE_LEN)
        addr = 20 * "\0"
        aset.add(addr)
        self.assertNotIn(addr, aset)
        self.assertEqual(len(aset), 0)

    # very unlikely to fail, though it isn't deterministic, so may fail somtimes.
    # If it fails repeatedly, there's probably a significant problem
    def test_false_positives(self):
        aset = AddressSet(1024, bytes_per_addr=8)
        rand_byte_count = aset._hash_bytes + aset._bytes_per_addr
        nonrand_prefix  = (20 - rand_byte_count) * "\0"
        for i in range(aset._max_len):
            aset.add(nonrand_prefix + "".join(chr(random.randrange(256)) for i in range(rand_byte_count)))
        for i in range(8192):
            self.assertNotIn(
                nonrand_prefix + "".join(chr(random.randrange(256)) for i in range(rand_byte_count)),
                aset)

    def test_file(self):
        aset = AddressSet(self.TABLE_LEN)
        addr = "".join(chr(b) for b in range(20))
        aset.add(addr)
        dbfile = tempfile.TemporaryFile()
        aset.tofile(dbfile)
        dbfile.seek(0)
        aset = AddressSet.fromfile(dbfile)
        self.assertTrue(dbfile.closed)  # should be closed by AddressSet in read-only mode
        self.assertIn(addr, aset)
        self.assertEqual(len(aset), 1)

    def test_file_update(self):
        aset   = AddressSet(self.TABLE_LEN)
        dbfile = tempfile.NamedTemporaryFile(delete=False)
        try:
            aset.tofile(dbfile)
            dbfile.seek(0)
            aset = AddressSet.fromfile(dbfile, mmap_access=mmap.ACCESS_WRITE)
            addr = "".join(chr(b) for b in range(20))
            aset.add(addr)
            aset.close()
            self.assertTrue(dbfile.closed)
            dbfile = open(dbfile.name, "rb")
            aset = AddressSet.fromfile(dbfile)
            self.assertIn(addr, aset)
            self.assertEqual(len(aset), 1)
        finally:
            aset.close()
            dbfile.close()
            os.remove(dbfile.name)

    def test_pickle_mmap(self):
        aset = AddressSet(self.TABLE_LEN)
        addr = "".join(chr(b) for b in range(20))
        aset.add(addr)
        dbfile = tempfile.NamedTemporaryFile(delete=False)
        try:
            aset.tofile(dbfile)
            dbfile.seek(0)
            aset = AddressSet.fromfile(dbfile)  # now it's an mmap
            pickled = pickle.dumps(aset, protocol=pickle.HIGHEST_PROTOCOL)
            aset.close()  # also closes the file
            aset = pickle.loads(pickled)
            self.assertIn(addr, aset)
            self.assertEqual(len(aset), 1)
        finally:
            aset.close()
            dbfile.close()
            os.remove(dbfile.name)


class TestRecoveryFromAddressDB(unittest.TestCase):

    def addressdb_tester(self, wallet_type, the_address_limit, correct_mnemonic, test_path, test_address_db, **kwds):
        assert the_address_limit > 1

        #Check to see if the AddressDB exists (and if not, skip)
        if not os.path.isfile("./btcrecover/test/test-addressdbs/" + test_address_db):
            raise unittest.SkipTest("requires ./btcrecover/test/test-addressdbs/" + test_address_db)

        # Test Basic BIP44 AddressDB Search
        addressdb = AddressSet.fromfile(open("./btcrecover/test/test-addressdbs/" + test_address_db, "rb"), preload=False)
        wallet = wallet_type.create_from_params(hash160s=addressdb, address_limit=the_address_limit, path=test_path)

        # Convert the mnemonic string into a mnemonic_ids_guess
        wallet.config_mnemonic(correct_mnemonic, **kwds)
        correct_mnemonic_ids = btcrseed.mnemonic_ids_guess

        # Creates wrong mnemonic id guesses
        wrong_mnemonic_iter = wallet.performance_iterator()

        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.__next__(), wrong_mnemonic_iter.__next__())), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.__next__(), correct_mnemonic_ids, wrong_mnemonic_iter.__next__())), (correct_mnemonic_ids, 2))

        # Make sure the address_limit is respected (note the "the_address_limit-1" below)
        wallet = wallet_type.create_from_params(hash160s=addressdb, address_limit=the_address_limit-1, path=test_path)
        wallet.config_mnemonic(correct_mnemonic, **kwds)
        self.assertEqual(wallet.return_verified_password_or_false(
            (correct_mnemonic_ids,)), (False, 1))


    #BCH AddressDB Tests
    # m/44'/145'/0'/0/1	bitcoincash:qrdupm96x04u3ssjnuj7lpy7adt9y34p5vzh95y0y7
    def test_addressdb_bip44_bch(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/145'/0'/0", "addresses-BCH-Test.db")

    # BCH AddressDB + BIP39 Passphrase Test
    # m/44'/145'/0'/0/1	bitcoincash:qprwa49yg44mj7geswgdmlylkp9pff32c5kr8a2wq3
    def test_addressdb_bip44_bch_passphrase(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/145'/0'/0", "addresses-BCH-Test.db", passphrase=u"youtube")

    # BTC AddressDB Tests
    #m/44'/0'/1'/0/1	1Bi3vKepTDmrRYC59WjaGDVDrg8qPsrc31
    def test_addressdb_bip44_btc(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/0'/1'/0", "addresses-BTC-Test.db")

    #m/49'/0'/1'/0/1	3GHFddEy3hPdwqh6gsTRfAZX83FfHKDNqF
    def test_addressdb_bip49_btc(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/49'/0'/1'/0", "addresses-BTC-Test.db")

    #m/84'/0'/1'/0/1	bc1ql4vgz4f8qef29x224935yxtun44prgr3eh06jh
    def test_addressdb_bip84_btc(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/84'/0'/1'/0", "addresses-BTC-Test.db")


    #LTC AddressDB Tests
    #m/44'/2'/1'/0/1	LgXiUTLMKcoaqvUPMNJo1RmpAGFMHD75tr
    def test_addressdb_bip44_ltc(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/2'/1'/0", "addresses-LTC-Test.db")

    #m/49'/2'/1'/0/1	MQ9ucyhhaEncRmdL3uq9XhzDre37mvFTCf
    def test_addressdb_bip49_ltc(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/49'/2'/1'/0", "addresses-LTC-Test.db")

    #m/84'/2'/1'/0/1	ltc1qgpn2phk8c7k966xjufrrll59qa8wnvnx68jtt6
    def test_addressdb_bip84_ltc(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/84'/2'/1'/0", "addresses-LTC-Test.db")


    #VTC AddressDB Tests
    # m/44'/28'/1'/0/1	VuMksxrDy48HZr15WR3Lwn6yvLKhuHgEUc
    def test_addressdb_bip44_vtc(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/28'/1'/0", "addresses-VTC-Test.db")

    # m/49'/28'/1'/0/1	3LSAzLG2WuzHABHoi3FiGvv4BqvvwnADCq
    def test_addressdb_bip49_vtc(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/49'/28'/1'/0", "addresses-VTC-Test.db")

    # m/84'/28'/1'/0/1	vtc1qpuw3nh0xfa4tcvxp3q8dc2cqhqtgsf4xg6r273
    def test_addressdb_bip84_vtc(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/84'/28'/1'/0", "addresses-VTC-Test.db")


    #MONA AddressDB Tests
    # m/44'/22'/1'/0/1	MPEbQUqKXPf8A9TCQTiGPhMcRBPwySroHg
    def test_addressdb_bip44_mona(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/44'/22'/1'/0", "addresses-MONA-Test.db")

    # m/49'/22'/1'/0/1	PNJmRN936aqgzuyXaRKiEHsy5mHKw4QWqn
    def test_addressdb_bip49_mona(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/49'/22'/1'/0", "addresses-MONA-Test.db")

    # m/84'/22'/1'/0/1	mona1qx9kllhxc4u4evjdhyejsseyqntjursxtewdcmm
    def test_addressdb_bip84_mona(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 2, "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby", "m/84'/22'/1'/0", "addresses-MONA-Test.db")

    #DGB AddressDB Tests
    # m/44'/20'/0'/4	D8uui9mGXztcpZy5t5jWpSimCCyEDjYRHY
    def test_addressdb_bip44_dgb(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 5, "barrel tag debate reopen federal fee soda fog twelve garage sweet current", "m/44'/20'/0'/0", "addresses-DGB-Test.db")

    # m/49'/20'/0'/4	SjM4p9vWB7GvsiNMgyZef67SJz3SgmPwhj
    def test_addressdb_bip49_dgb(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 5, "barrel tag debate reopen federal fee soda fog twelve garage sweet current", "m/49'/20'/0'/0", "addresses-DGB-Test.db")

    # m/84'/20'/0'/4	dgb1qmtpcmpt5amuvvwvpelh220ec2ck7q4prsy2tqy
    def test_addressdb_bip84_dgb(self):
        self.addressdb_tester(btcrseed.WalletBIP39, 5, "barrel tag debate reopen federal fee soda fog twelve garage sweet current", "m/84'/20'/0'/0", "addresses-DGB-Test.db")


class TestSeedTypos(unittest.TestCase):
    XPUB = "xpub6BgCDhMefYxRS1gbVbxyokYzQji65v1eGJXGEiGdoobvFBShcNeJt97zoJBkNtbASLyTPYXJHRvkb3ahxaVVGEtC1AD4LyuBXULZcfCjBZx"

    def seed_tester(self, the_mpk, correct_mnemonic, mnemonic_guess, typos = None, big_typos = 0):
        correct_mnemonic = correct_mnemonic.split()
        assert mnemonic_guess.split() != correct_mnemonic
        assert typos or big_typos
        btcrseed.loaded_wallet = btcrseed.WalletBIP39.create_from_params(mpk=the_mpk)
        btcrseed.loaded_wallet.config_mnemonic(mnemonic_guess)
        self.assertEqual(
            btcrseed.run_btcrecover(typos or big_typos, big_typos, extra_args="--threads 1".split()),
            tuple(correct_mnemonic))

    def test_delete(self):
        self.seed_tester(self.XPUB,
            "certain      come keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "certain come come keen collect slab gauge photo inside mechanic deny leader drop",  # guess
            typos=1)

    def test_replacewrong(self):
        self.seed_tester(self.XPUB,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "certain X    keen collect slab gauge photo inside mechanic deny leader drop",  # guess
            big_typos=1)

    def test_insert(self):
        self.seed_tester(self.XPUB,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "        come keen collect slab gauge photo inside mechanic deny leader drop",  # guess
            big_typos=1)

    def test_swap(self):
        self.seed_tester(self.XPUB,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "certain keen come collect slab gauge photo inside mechanic deny leader drop",  # guess
            typos=1)

    def test_replace(self):
        self.seed_tester(self.XPUB,
            "certain  come keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "disagree come keen collect slab gauge photo inside mechanic deny leader drop",  # guess
            big_typos=1)

    def test_replaceclose(self):
        self.seed_tester(self.XPUB,
            "certain come   keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "certain become keen collect slab gauge photo inside mechanic deny leader drop",  # guess
            typos=1)

    def test_replaceclose_firstfour(self):
        self.seed_tester(self.XPUB,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "cere    come keen coll    slab gaug  phot  insi   mech     deny lead   drop",  # guess
            # "cere" is close to "cert" in the en-firstfour language, even though "cereal" is not close to "certain"
            typos=1)

class TestRecoverySeedListsGenerators(unittest.TestCase):

    # Both the tokenlist generator and seedlist generator should generate the same output, the list of passwords below.
    expected_passwordlist = [[
    ['ocean', 'hidden', 'kidney', 'famous', 'rich', 'season', 'gloom', 'husband', 'spring', 'boy', 'attitude', 'convince'],
    ['ocean', 'hidden', 'kidney', 'famous', 'rich', 'season', 'gloom', 'husband', 'spring', 'boy', 'convince', 'attitude'],
    ['ocean', 'hidden', 'kidney', 'famous', 'rich', 'season', 'gloom', 'husband', 'spring', 'attitude', 'boy', 'convince'],
    ['ocean', 'hidden', 'kidney', 'famous', 'rich', 'season', 'gloom', 'husband', 'spring', 'attitude', 'convince', 'boy'],
    ['ocean', 'hidden', 'kidney', 'famous', 'rich', 'season', 'gloom', 'husband', 'spring', 'convince', 'boy', 'attitude'],
    ['ocean', 'hidden', 'kidney', 'famous', 'rich', 'season', 'gloom', 'husband', 'spring', 'convince', 'attitude', 'boy']
    ]]

    def seedlist_tester(self, seedlistfile):
        # Check to see if the Seed List file exists (and if not, skip)
        if not os.path.isfile("./btcrecover/test/test-listfiles/" + seedlistfile):
            raise unittest.SkipTest("requires ./btcrecover/test/test-listfiles/" + seedlistfile)

        args = " --listpass --seedgenerator".split()

        btcrpass.parse_arguments(["--passwordlist"] + ["./btcrecover/test/test-listfiles/" + seedlistfile] + args, disable_security_warning_param = True)
        pwl_it, skipped = btcrpass.password_generator_factory(sys.maxsize)
        generated_passwords = list(pwl_it)
        self.assertEqual(generated_passwords, self.expected_passwordlist)

    def test_seedlist_raw(self):
        self.seedlist_tester("SeedListTest.txt")

    def test_seedlist_pylist(self):
        self.seedlist_tester("SeedListTest_pylist.txt")

    def test_seedlist_pytupe(self):
        self.seedlist_tester("SeedListTest_pytupe.txt")

    def test_tokenlist(self):
        # Check to see if the Token List file exists (and if not, skip)
        if not os.path.isfile("./btcrecover/test/test-listfiles/SeedTokenListTest.txt"):
            raise unittest.SkipTest("requires ./btcrecover/test/test-listfiles/SeedTokenListTest.txt")

        args = " --listpass --seedgenerator --max-tokens 12 --min-tokens 12".split()

        btcrpass.parse_arguments(["--tokenlist"] + ["./btcrecover/test/test-listfiles/SeedTokenListTest.txt"] + args, disable_security_warning_param = True)
        tok_it, skipped = btcrpass.password_generator_factory(sys.maxsize)
        generated_passwords = list(tok_it)
        self.assertEqual(generated_passwords, self.expected_passwordlist)

# All seed tests except TestAddressSet.test_false_positives are quick
class QuickTests(unittest.TestSuite):
    def __init__(self):
        super(QuickTests, self).__init__()
        for suite in unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]):
            if isinstance(suite._tests[0], TestAddressSet):
                for test_num in range(len(suite._tests)):
                    if suite._tests[test_num]._testMethodName == "test_false_positives":
                        del suite._tests[test_num]
                        break
            self.addTests(suite)


if __name__ == '__main__':

    import argparse

    # Add one new argument to those already provided by unittest.main()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--no-buffer", action="store_true")
    args, unittest_args = parser.parse_known_args()
    sys.argv[1:] = unittest_args

    unittest.main(buffer = not args.no_buffer)
