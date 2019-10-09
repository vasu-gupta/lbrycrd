#ifndef CLAIMTRIE_TRIE_H
#define CLAIMTRIE_TRIE_H

#include <claimtrie/data.h>
#include <claimtrie/prefixtrie.h>
#include <claimtrie/txoutpoint.h>
#include <claimtrie/uints.h>
#include <dbwrapper.h>

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <utility>

// leveldb keys
#define TRIE_NODE 'n'
#define TRIE_NODE_CHILDREN 'b'
#define CLAIM_BY_ID 'i'
#define CLAIM_QUEUE_ROW 'r'
#define CLAIM_QUEUE_NAME_ROW 'm'
#define CLAIM_EXP_QUEUE_ROW 'e'
#define SUPPORT 's'
#define SUPPORT_QUEUE_ROW 'u'
#define SUPPORT_QUEUE_NAME_ROW 'p'
#define SUPPORT_EXP_QUEUE_ROW 'x'

CUint256 getValueHash(const CTxOutPoint& outPoint, int nHeightOfLastTakeover);

struct CClaimNsupports
{
    CClaimNsupports() = default;
    CClaimNsupports(CClaimNsupports&&) = default;
    CClaimNsupports(const CClaimNsupports&) = default;

    CClaimNsupports& operator=(CClaimNsupports&&) = default;
    CClaimNsupports& operator=(const CClaimNsupports&) = default;

    CClaimNsupports(CClaimValue claim, int64_t effectiveAmount, std::vector<CSupportValue> supports = {});

    bool IsNull() const;

    CClaimValue claim;
    int64_t effectiveAmount = 0;
    std::vector<CSupportValue> supports;
};

struct CClaimSupportToName
{
    CClaimSupportToName(std::string name, int nLastTakeoverHeight, std::vector<CClaimNsupports> claimsNsupports, std::vector<CSupportValue> unmatchedSupports);

    const CClaimNsupports& find(const CUint160& claimId) const;
    const CClaimNsupports& find(const std::string& partialId) const;

    const std::string name;
    const int nLastTakeoverHeight;
    const std::vector<CClaimNsupports> claimsNsupports;
    const std::vector<CSupportValue> unmatchedSupports;
};

class CClaimTrie : public CPrefixTrie<std::string, CClaimTrieData>
{
public:
    CClaimTrie() = default;
    CClaimTrie(CClaimTrie&&) = delete;
    CClaimTrie(const CClaimTrie&) = delete;
    CClaimTrie(bool fMemory,
               bool fWipe,
               int nNormalizedNameForkHeight,
               int64_t nOriginalClaimExpirationTime,
               int64_t nExtendedClaimExpirationTime,
               int64_t nExtendedClaimExpirationForkHeight,
               int64_t nAllClaimsInMerkleForkHeight,
               int proportionalDelayFactor = 32, std::size_t cacheMB = 200);

    CClaimTrie& operator=(CClaimTrie&&) = delete;
    CClaimTrie& operator=(const CClaimTrie&) = delete;

    bool SyncToDisk();

    friend class CClaimTrieCacheBase;
    friend struct ClaimTrieChainFixture;
    friend class CClaimTrieCacheHashFork;
    friend class CClaimTrieCacheExpirationFork;
    friend class CClaimTrieCacheNormalizationFork;
    friend bool getClaimById(const CUint160&, std::string&, CClaimValue*);
    friend bool getClaimById(const std::string&, std::string&, CClaimValue*);

    std::size_t getTotalNamesInTrie() const;
    std::size_t getTotalClaimsInTrie() const;
    int64_t getTotalValueOfClaimsInTrie(bool fControllingOnly) const;

protected:
    int nNextHeight = 0;
    std::unique_ptr<CDBWrapper> db;
    const int nProportionalDelayFactor = 0;

    const int nNormalizedNameForkHeight = -1;
    const int64_t nOriginalClaimExpirationTime = -1;
    const int64_t nExtendedClaimExpirationTime = -1;
    const int64_t nExtendedClaimExpirationForkHeight = -1;
    const int64_t nAllClaimsInMerkleForkHeight = -1;
};

struct CClaimTrieProofNode
{
    CClaimTrieProofNode(std::vector<std::pair<unsigned char, CUint256>> children, bool hasValue, CUint256 valHash);

    CClaimTrieProofNode(CClaimTrieProofNode&&) = default;
    CClaimTrieProofNode(const CClaimTrieProofNode&) = default;
    CClaimTrieProofNode& operator=(CClaimTrieProofNode&&) = default;
    CClaimTrieProofNode& operator=(const CClaimTrieProofNode&) = default;

    std::vector<std::pair<unsigned char, CUint256>> children;
    bool hasValue;
    CUint256 valHash;
};

struct CClaimTrieProof
{
    CClaimTrieProof() = default;
    CClaimTrieProof(CClaimTrieProof&&) = default;
    CClaimTrieProof(const CClaimTrieProof&) = default;
    CClaimTrieProof& operator=(CClaimTrieProof&&) = default;
    CClaimTrieProof& operator=(const CClaimTrieProof&) = default;

    std::vector<std::pair<bool, CUint256>> pairs;
    std::vector<CClaimTrieProofNode> nodes;
    int nHeightOfLastTakeover = 0;
    bool hasValue = false;
    CTxOutPoint outPoint;
};

template <typename T>
class COptional
{
    bool own;
    T* value;
public:
    COptional(T* value = nullptr) : own(false), value(value) {}
    COptional(COptional&& o)
    {
        own = o.own;
        value = o.value;
        o.own = false;
        o.value = nullptr;
    }
    COptional(T&& o) : own(true)
    {
        value = new T(std::move(o));
    }
    ~COptional()
    {
        if (own)
            delete value;
    }
    COptional& operator=(COptional&&) = delete;
    bool unique() const
    {
        return own;
    }
    operator bool() const
    {
        return value;
    }
    operator T*() const
    {
        return value;
    }
    T* operator->() const
    {
        return value;
    }
    operator T&() const
    {
        return *value;
    }
    T& operator*() const
    {
        return *value;
    }
};

template <typename T>
using queueEntryType = std::pair<std::string, T>;

typedef std::vector<queueEntryType<CClaimValue>> claimQueueRowType;
typedef std::map<int, claimQueueRowType> claimQueueType;

typedef std::vector<queueEntryType<CSupportValue>> supportQueueRowType;
typedef std::map<int, supportQueueRowType> supportQueueType;

typedef std::vector<CTxOutPointHeightType> queueNameRowType;
typedef std::map<std::string, queueNameRowType> queueNameType;

typedef std::vector<CNameOutPointHeightType> insertUndoType;

typedef std::vector<CNameOutPointType> expirationQueueRowType;
typedef std::map<int, expirationQueueRowType> expirationQueueType;

typedef std::set<CClaimValue> claimIndexClaimListType;
typedef std::vector<CClaimIndexElement> claimIndexElementListType;

class CBlockIndex;

class CClaimTrieCacheBase
{
public:
    explicit CClaimTrieCacheBase(CClaimTrie* base);
    virtual ~CClaimTrieCacheBase() = default;

    CUint256 getMerkleHash();

    bool flush();
    bool empty() const;
    bool checkConsistency() const;
    bool ReadFromDisk(int nHeight, const CUint256& rootHash);

    bool haveClaim(const std::string& name, const CTxOutPoint& outPoint) const;
    bool haveClaimInQueue(const std::string& name, const CTxOutPoint& outPoint, int& nValidAtHeight) const;

    bool haveSupport(const std::string& name, const CTxOutPoint& outPoint) const;
    bool haveSupportInQueue(const std::string& name, const CTxOutPoint& outPoint, int& nValidAtHeight) const;

    bool addClaim(const std::string& name, const CTxOutPoint& outPoint, const CUint160& claimId, int64_t nAmount, int nHeight);
    bool undoAddClaim(const std::string& name, const CTxOutPoint& outPoint, int nHeight);

    bool spendClaim(const std::string& name, const CTxOutPoint& outPoint, int nHeight, int& nValidAtHeight);
    bool undoSpendClaim(const std::string& name, const CTxOutPoint& outPoint, const CUint160& claimId, int64_t nAmount, int nHeight, int nValidAtHeight);

    bool addSupport(const std::string& name, const CTxOutPoint& outPoint, int64_t nAmount, const CUint160& supportedClaimId, int nHeight);
    bool undoAddSupport(const std::string& name, const CTxOutPoint& outPoint, int nHeight);

    bool spendSupport(const std::string& name, const CTxOutPoint& outPoint, int nHeight, int& nValidAtHeight);
    bool undoSpendSupport(const std::string& name, const CTxOutPoint& outPoint, const CUint160& supportedClaimId, int64_t nAmount, int nHeight, int nValidAtHeight);

    virtual bool incrementBlock(insertUndoType& insertUndo,
        claimQueueRowType& expireUndo,
        insertUndoType& insertSupportUndo,
        supportQueueRowType& expireSupportUndo,
        std::vector<std::pair<std::string, int>>& takeoverHeightUndo);

    virtual bool decrementBlock(insertUndoType& insertUndo,
        claimQueueRowType& expireUndo,
        insertUndoType& insertSupportUndo,
        supportQueueRowType& expireSupportUndo);

    virtual bool getProofForName(const std::string& name, CClaimTrieProof& proof);
    virtual bool getInfoForName(const std::string& name, CClaimValue& claim) const;

    virtual int expirationTime() const;

    virtual bool finalizeDecrement(std::vector<std::pair<std::string, int>>& takeoverHeightUndo);

    virtual CClaimSupportToName getClaimsForName(const std::string& name) const;

    CClaimTrie::const_iterator find(const std::string& name) const;
    void iterate(std::function<void(const std::string&, const CClaimTrieData&)> callback) const;

    void dumpToLog(CClaimTrie::const_iterator it, bool diffFromBase = true) const;
    virtual std::string adjustNameForValidHeight(const std::string& name, int validHeight) const;

protected:
    CClaimTrie* base;
    CClaimTrie nodesToAddOrUpdate; // nodes pulled in from base (and possibly modified thereafter), written to base on flush
    std::unordered_set<std::string> nodesAlreadyCached; // set of nodes already pulled into cache from base
    std::unordered_set<std::string> namesToCheckForTakeover; // takeover numbers are updated on increment

    virtual CUint256 recursiveComputeMerkleHash(CClaimTrie::iterator& it);
    virtual bool recursiveCheckConsistency(CClaimTrie::const_iterator& it, std::string& failed) const;

    virtual bool insertClaimIntoTrie(const std::string& name, const CClaimValue& claim, bool fCheckTakeover);
    virtual bool removeClaimFromTrie(const std::string& name, const CTxOutPoint& outPoint, CClaimValue& claim, bool fCheckTakeover);

    virtual bool insertSupportIntoMap(const std::string& name, const CSupportValue& support, bool fCheckTakeover);
    virtual bool removeSupportFromMap(const std::string& name, const CTxOutPoint& outPoint, CSupportValue& support, bool fCheckTakeover);

    supportEntryType getSupportsForName(const std::string& name) const;

    int getDelayForName(const std::string& name) const;
    virtual int getDelayForName(const std::string& name, const CUint160& claimId) const;

    CClaimTrie::iterator cacheData(const std::string& name, bool create = true);

    bool getLastTakeoverForName(const std::string& name, CUint160& claimId, int& takeoverHeight) const;

    int getNumBlocksOfContinuousOwnership(const std::string& name) const;

    void reactivateClaim(const expirationQueueRowType& row, int height, bool increment);
    void reactivateSupport(const expirationQueueRowType& row, int height, bool increment);

    expirationQueueType expirationQueueCache;
    expirationQueueType supportExpirationQueueCache;

    int nNextHeight; // Height of the block that is being worked on, which is
                     // one greater than the height of the chain's tip

private:
    CUint256 hashBlock;

    std::unordered_map<std::string, std::pair<CUint160, int>> takeoverCache;

    claimQueueType claimQueueCache; // claims not active yet: to be written to disk on flush
    queueNameType claimQueueNameCache;
    supportQueueType supportQueueCache; // supports not active yet: to be written to disk on flush
    queueNameType supportQueueNameCache;
    claimIndexElementListType claimsToAddToByIdIndex; // written to index on flush
    claimIndexClaimListType claimsToDeleteFromByIdIndex;

    std::unordered_map<std::string, supportEntryType> supportCache;  // to be added/updated to base (and disk) on flush
    std::unordered_set<std::string> nodesToDelete; // to be removed from base (and disk) on flush

    bool clear();

    void markAsDirty(const std::string& name, bool fCheckTakeover);
    bool removeSupport(const std::string& name, const CTxOutPoint& outPoint, int nHeight, int& nValidAtHeight, bool fCheckTakeover);
    bool removeClaim(const std::string& name, const CTxOutPoint& outPoint, int nHeight, int& nValidAtHeight, bool fCheckTakeover);

    template <typename T>
    void insertRowsFromQueue(std::vector<T>& result, const std::string& name) const;

    template <typename T>
    std::vector<queueEntryType<T>>* getQueueCacheRow(int nHeight, bool createIfNotExists);

    template <typename T>
    COptional<const std::vector<queueEntryType<T>>> getQueueCacheRow(int nHeight) const;

    template <typename T>
    queueNameRowType* getQueueCacheNameRow(const std::string& name, bool createIfNotExists);

    template <typename T>
    COptional<const queueNameRowType> getQueueCacheNameRow(const std::string& name) const;

    template <typename T>
    expirationQueueRowType* getExpirationQueueCacheRow(int nHeight, bool createIfNotExists);

    template <typename T>
    bool haveInQueue(const std::string& name, const CTxOutPoint& outPoint, int& nValidAtHeight) const;

    template <typename T>
    T add(const std::string& name, const CTxOutPoint& outPoint, const CUint160& claimId, int64_t nAmount, int nHeight);

    template <typename T>
    bool remove(T& value, const std::string& name, const CTxOutPoint& outPoint, int nHeight, int& nValidAtHeight, bool fCheckTakeover = false);

    template <typename T>
    bool addToQueue(const std::string& name, const T& value);

    template <typename T>
    bool removeFromQueue(const std::string& name, const CTxOutPoint& outPoint, T& value);

    template <typename T>
    bool addToCache(const std::string& name, const T& value, bool fCheckTakeover = false);

    template <typename T>
    bool removeFromCache(const std::string& name, const CTxOutPoint& outPoint, T& value, bool fCheckTakeover = false);

    template <typename T>
    bool undoSpend(const std::string& name, const T& value, int nValidAtHeight);

    template <typename T>
    void undoIncrement(insertUndoType& insertUndo, std::vector<queueEntryType<T>>& expireUndo, std::set<T>* deleted = nullptr);

    template <typename T>
    void undoDecrement(insertUndoType& insertUndo, std::vector<queueEntryType<T>>& expireUndo, std::vector<CClaimIndexElement>* added = nullptr, std::set<T>* deleted = nullptr);

    template <typename T>
    void undoIncrement(const std::string& name, insertUndoType& insertUndo, std::vector<queueEntryType<T>>& expireUndo);

    template <typename T>
    void reactivate(const expirationQueueRowType& row, int height, bool increment);

    // for unit test
    friend struct ClaimTrieChainFixture;
    friend class CClaimTrieCacheTest;
};

#endif // CLAIMTRIE_TRIE_H
