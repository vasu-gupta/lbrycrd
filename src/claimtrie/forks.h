
#ifndef CLAIMTRIE_FORKS_H
#define CLAIMTRIE_FORKS_H

#include <claimtrie/trie.h>

class CClaimTrieCacheExpirationFork : public CClaimTrieCacheBase
{
public:
    explicit CClaimTrieCacheExpirationFork(CClaimTrie* base);

    int expirationTime() const override;

    virtual void initializeIncrement();
    bool finalizeDecrement(std::vector<std::pair<std::string, int>>& takeoverHeightUndo) override;

    bool incrementBlock(insertUndoType& insertUndo,
        claimQueueRowType& expireUndo,
        insertUndoType& insertSupportUndo,
        supportQueueRowType& expireSupportUndo,
        std::vector<std::pair<std::string, int>>& takeoverHeightUndo) override;

    bool decrementBlock(insertUndoType& insertUndo,
        claimQueueRowType& expireUndo,
        insertUndoType& insertSupportUndo,
        supportQueueRowType& expireSupportUndo) override;

protected:
    int expirationHeight;

private:
    bool forkForExpirationChange(bool increment);
};

class CClaimTrieCacheNormalizationFork : public CClaimTrieCacheExpirationFork
{
public:
    explicit CClaimTrieCacheNormalizationFork(CClaimTrie* base);

    bool shouldNormalize() const;

    // lower-case and normalize any input string name
    // see: https://unicode.org/reports/tr15/#Norm_Forms
    std::string normalizeClaimName(const std::string& name, bool force = false) const; // public only for validating name field on update op

    bool incrementBlock(insertUndoType& insertUndo,
        claimQueueRowType& expireUndo,
        insertUndoType& insertSupportUndo,
        supportQueueRowType& expireSupportUndo,
        std::vector<std::pair<std::string, int>>& takeoverHeightUndo) override;

    bool decrementBlock(insertUndoType& insertUndo,
        claimQueueRowType& expireUndo,
        insertUndoType& insertSupportUndo,
        supportQueueRowType& expireSupportUndo) override;

    bool getProofForName(const std::string& name, CClaimTrieProof& proof) override;
    bool getInfoForName(const std::string& name, CClaimValue& claim) const override;
    CClaimSupportToName getClaimsForName(const std::string& name) const override;
    std::string adjustNameForValidHeight(const std::string& name, int validHeight) const override;

protected:
    bool insertClaimIntoTrie(const std::string& name, const CClaimValue& claim, bool fCheckTakeover) override;
    bool removeClaimFromTrie(const std::string& name, const CTxOutPoint& outPoint, CClaimValue& claim, bool fCheckTakeover) override;

    bool insertSupportIntoMap(const std::string& name, const CSupportValue& support, bool fCheckTakeover) override;
    bool removeSupportFromMap(const std::string& name, const CTxOutPoint& outPoint, CSupportValue& support, bool fCheckTakeover) override;

    int getDelayForName(const std::string& name, const CUint160& claimId) const override;

private:
    bool overrideInsertNormalization;
    bool overrideRemoveNormalization;

    bool normalizeAllNamesInTrieIfNecessary(insertUndoType& insertUndo,
        claimQueueRowType& removeUndo,
        insertUndoType& insertSupportUndo,
        supportQueueRowType& expireSupportUndo,
        std::vector<std::pair<std::string, int>>& takeoverHeightUndo);
};

class CClaimTrieCacheHashFork : public CClaimTrieCacheNormalizationFork
{
public:
    explicit CClaimTrieCacheHashFork(CClaimTrie* base);

    bool getProofForName(const std::string& name, CClaimTrieProof& proof) override;
    bool getProofForName(const std::string& name, CClaimTrieProof& proof, const std::function<bool(const CClaimValue&)>& comp);
    void initializeIncrement() override;
    bool finalizeDecrement(std::vector<std::pair<std::string, int>>& takeoverHeightUndo) override;

    bool allowSupportMetadata() const;

protected:
    CUint256 recursiveComputeMerkleHash(CClaimTrie::iterator& it) override;
    bool recursiveCheckConsistency(CClaimTrie::const_iterator& it, std::string& failed) const override;

private:
    void copyAllBaseToCache();
};

typedef CClaimTrieCacheHashFork CClaimTrieCache;

#endif // CLAIMTRIE_FORKS_H
