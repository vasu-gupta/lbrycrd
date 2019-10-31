
#ifndef CLAIMTRIE_DATA_H
#define CLAIMTRIE_DATA_H

#include <txoutpoint.h>
#include <uints.h>

#include <string>
#include <vector>

struct CClaimValue
{
    CTxOutPoint outPoint;
    CUint160 claimId;
    int64_t nAmount = 0;
    int64_t nEffectiveAmount = 0;
    int nHeight = 0;
    int nValidAtHeight = 0;

    CClaimValue() = default;
    CClaimValue(CTxOutPoint outPoint, CUint160 claimId, int64_t nAmount, int nHeight, int nValidAtHeight);

    CClaimValue(CClaimValue&&) = default;
    CClaimValue(const CClaimValue&) = default;
    CClaimValue& operator=(CClaimValue&&) = default;
    CClaimValue& operator=(const CClaimValue&) = default;

    bool operator<(const CClaimValue& other) const;
    bool operator==(const CClaimValue& other) const;
    bool operator!=(const CClaimValue& other) const;

    std::string ToString() const;
};

struct CSupportValue
{
    CTxOutPoint outPoint;
    CUint160 supportedClaimId;
    int64_t nAmount = 0;
    int nHeight = 0;
    int nValidAtHeight = 0;

    CSupportValue() = default;
    CSupportValue(CTxOutPoint outPoint, CUint160 supportedClaimId, int64_t nAmount, int nHeight, int nValidAtHeight);

    CSupportValue(CSupportValue&&) = default;
    CSupportValue(const CSupportValue&) = default;
    CSupportValue& operator=(CSupportValue&&) = default;
    CSupportValue& operator=(const CSupportValue&) = default;

    bool operator==(const CSupportValue& other) const;
    bool operator!=(const CSupportValue& other) const;

    std::string ToString() const;
};

typedef std::vector<CClaimValue> claimEntryType;
typedef std::vector<CSupportValue> supportEntryType;

struct CClaimTrieData
{
    CUint256 hash;
    claimEntryType claims;
    int nHeightOfLastTakeover = 0;

    CClaimTrieData() = default;
    CClaimTrieData(CClaimTrieData&&) = default;
    CClaimTrieData(const CClaimTrieData&) = default;
    CClaimTrieData& operator=(CClaimTrieData&&) = default;
    CClaimTrieData& operator=(const CClaimTrieData& d) = default;

    bool insertClaim(const CClaimValue& claim);
    bool removeClaim(const CTxOutPoint& outPoint, CClaimValue& claim);
    bool getBestClaim(CClaimValue& claim) const;
    bool haveClaim(const CTxOutPoint& outPoint) const;
    void reorderClaims(const supportEntryType& support);

    bool operator==(const CClaimTrieData& other) const;
    bool operator!=(const CClaimTrieData& other) const;

    bool empty() const;
};

struct CTxOutPointHeightType
{
    CTxOutPoint outPoint;
    int nHeight = 0;

    CTxOutPointHeightType() = default;
    CTxOutPointHeightType(CTxOutPoint outPoint, int nHeight);
};

struct CNameOutPointHeightType
{
    std::string name;
    CTxOutPoint outPoint;
    int nHeight = 0;

    CNameOutPointHeightType() = default;
    CNameOutPointHeightType(std::string name, CTxOutPoint outPoint, int nHeight);
};

struct CNameOutPointType
{
    std::string name;
    CTxOutPoint outPoint;

    CNameOutPointType() = default;
    CNameOutPointType(std::string name, CTxOutPoint outPoint);

    bool operator==(const CNameOutPointType& other) const;
};

#ifndef SWIG_INTERFACE

template <typename K, typename V>
bool equals(const std::pair<K, V>& pair, const CNameOutPointType& point)
{
    return pair.first == point.name && pair.second.outPoint == point.outPoint;
}

#endif // SWIG_INTERFACE

struct CClaimIndexElement
{
    std::string name;
    CClaimValue claim;

    CClaimIndexElement() = default;
    CClaimIndexElement(std::string name, CClaimValue claim);
};

#endif // CLAIMTRIE_DATA_H
