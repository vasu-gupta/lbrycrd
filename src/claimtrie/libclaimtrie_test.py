
from libclaimtrie import *
import unittest

class TestClaimTrieTypes(unittest.TestCase):
    def setUp(self):
        self.uint256s = "1234567890987654321012345678909876543210123456789098765432101234"
        self.uint160 = CUint160S("1234567890987654321012345678909876543210")
        self.uint = CUint256S(self.uint256s)
        self.txp = CTxOutPoint(self.uint, 1)

    def assertClaimEqual(self, claim, txo, cid, amount, effe, height, validHeight, msg):
        self.assertEqual(claim.outPoint, txo, msg)
        self.assertEqual(claim.claimId, cid, msg)
        self.assertEqual(claim.nAmount, amount, msg)
        self.assertEqual(claim.nEffectiveAmount, effe, msg)
        self.assertEqual(claim.nHeight, height, msg)
        self.assertEqual(claim.nValidAtHeight, validHeight, msg)

    def assertSupportEqual(self, support, txo, cid, amount, height, validHeight, msg):
        self.assertEqual(support.outPoint, txo, msg)
        self.assertEqual(support.supportedClaimId, cid, msg)
        self.assertEqual(support.nAmount, amount, msg)
        self.assertEqual(support.nHeight, height, msg)
        self.assertEqual(support.nValidAtHeight, validHeight, msg)

    def test_uint256(self):
        uint = self.uint
        self.assertFalse(uint.IsNull(), "incorrect CUint256S or CBaseBlob::IsNull")
        self.assertEqual(uint.GetHex(), self.uint256s, "incorrect CBaseBlob::GetHex")
        self.assertEqual(uint.GetHex(), uint.ToString(), "incorrect CBaseBlob::ToString")
        self.assertEqual(uint.size(), 32, "incorrect CBaseBlob::size")
        copy = CUint256()
        self.assertNotEqual(copy, uint, "incorrect CBaseBlob::operator!=")
        self.assertTrue(copy.IsNull(), "incorrect CBaseBlob::IsNull")
        copy = CUint256(uint)
        self.assertEqual(copy, uint, "incorrect CBaseBlob::operator==")
        copy.SetNull()
        self.assertTrue(copy.IsNull()), "incorrect CBaseBlob::SetNull"

    def test_txoupoint(self):
        txp = self.txp
        uint = self.uint
        self.assertEqual(txp.hash, uint, "incorrect CTxOutPoint::CTxOutPoint")
        self.assertEqual(txp.n, 1, "incorrect CTxOutPoint::CTxOutPoint")
        self.assertFalse(txp.IsNull(), "incorrect CTxOutPoint::IsNull")
        pcopy = CTxOutPoint()
        self.assertTrue(pcopy.IsNull(), "incorrect CTxOutPoint::IsNull")
        self.assertEqual(pcopy.hash, CUint256(), "incorrect CTxOutPoint::CTxOutPoint")
        self.assertNotEqual(pcopy, txp, "incorrect CTxOutPoint::operator!=")
        self.assertIn(uint.ToString()[:10], txp.ToString(), "incorrect CTxOutPoint::ToString")

    def test_claim(self):
        txp = self.txp
        uint160 = self.uint160
        self.assertEqual(uint160.size(), 20, "incorrect CBaseBlob::size")
        claim = CClaimValue(txp, uint160, 20, 1, 10)
        self.assertClaimEqual(claim, txp, uint160, 20, 20, 1, 10, "incorrect CClaimValue::CClaimValue")

    def test_support(self):
        txp = self.txp
        uint160 = self.uint160
        claim = CClaimValue(txp, uint160, 20, 1, 10)
        support = CSupportValue(txp, uint160, 20, 1, 10)
        self.assertSupportEqual(support, claim.outPoint, claim.claimId, claim.nAmount, claim.nHeight, claim.nValidAtHeight, "incorrect CSupportValue::CSupportValue")

    def test_claimtrie_data(self):
        txp = self.txp
        uint160 = self.uint160
        data = CClaimTrieData()
        claim = CClaimValue(txp, uint160, 20, 1, 10)
        support = CSupportValue(txp, uint160, 20, 1, 10)
        self.assertTrue(data.empty(), "incorrect CClaimTrieData::empty")
        self.assertTrue(data.insertClaim(claim), "incorrect CClaimTrieData::insertClaim")
        self.assertFalse(data.empty(), "incorrect CClaimTrieData::empty")
        self.assertTrue(data.haveClaim(claim.outPoint), "incorrect CClaimTrieData::haveClaim")
        claim1 = CClaimValue()
        self.assertTrue(data.getBestClaim(claim1), "incorrect CClaimTrieData::getBestClaim")
        self.assertEqual(claim, claim1, "incorrect best claim")
        data.reorderClaims(supportEntryType(1, support))
        self.assertEqual(data.claims[0].nEffectiveAmount, 40, "incorrect CClaimTrieData::reorderClaims")

    def test_claimtrie(self):
        txp = self.txp
        uint160 = self.uint160
        claim = CClaimValue(txp, uint160, 20, 1, 10)
        data = CClaimTrieData()
        data.insertClaim(claim)
        in_memory = True; wipe = True; data_dir = "."
        trie = CClaimTrie(in_memory, wipe, data_dir)
        it = trie.insert("test", data)
        self.assertTrue(it, "incorrect CClaimTrie::insert")
        self.assertTrue(trie.contains("test"), "incorrect CClaimTrie::contains")
        self.assertFalse(trie.empty(), "incorrect CClaimTrie::empty")
        self.assertEqual(trie.height(), 1, "incorrect CClaimTrie::height")
        it = trie.find("test")
        self.assertTrue(it, "incorrect CClaimTrie::find")
        data = it.data()
        self.assertFalse(data.empty(), "incorrect iterator::data")
        it = trie.insert("tes", CClaimTrieData())
        self.assertEqual(trie.height(), 2, "incorrect CClaimTrie::height")
        self.assertTrue(it.hasChildren(), "incorrect iterator::hasChildren")
        children = it.children()
        self.assertEqual(children.size(), 1, "incorrect iterator::children")
        self.assertFalse(children[0].data().empty(), "incorrect data")
        self.assertEqual(trie.getTotalNamesInTrie(), 1, "incorrect CClaimTrie::getTotalNamesInTrie")
        self.assertEqual(trie.getTotalClaimsInTrie(), 1, "incorrect CClaimTrie::getTotalClaimsInTrie")
        cache = CClaimTrieCacheBase(trie)
        self.assertTrue(cache.empty(), "incorrect CClaimtrieCache::empty")
        self.assertTrue(cache.haveClaim("test", txp), "incorrect CClaimtrieCache::haveClaim")
        self.assertTrue(cache.addClaim("tes", txp, uint160, 20, 0), "incorrect CClaimtrieCache::addClaim")
        claimsToName = cache.getClaimsForName("test")
        claims = claimsToName.claimsNsupports
        self.assertEqual(claims.size(), 1, "incorrect CClaimTrieCache::getClaimsForName")
        self.assertFalse(claims[0].IsNull(), "incorrect CClaimNsupports::IsNull")

unittest.main()
