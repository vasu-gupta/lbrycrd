
#include <claimtrie/data.h>
#include <claimtrie/log.h>

#include <algorithm>
#include <sstream>

#define logPrint CLogPrint::global()

CClaimValue::CClaimValue(CTxOutPoint outPoint, CUint160 claimId, int64_t nAmount, int nHeight, int nValidAtHeight)
    : outPoint(std::move(outPoint)), claimId(std::move(claimId)), nAmount(nAmount), nEffectiveAmount(nAmount), nHeight(nHeight), nValidAtHeight(nValidAtHeight)
{
}

bool CClaimValue::operator<(const CClaimValue& other) const
{
    if (nEffectiveAmount < other.nEffectiveAmount)
        return true;
    if (nEffectiveAmount != other.nEffectiveAmount)
        return false;
    if (nHeight > other.nHeight)
        return true;
    if (nHeight != other.nHeight)
        return false;
    return outPoint != other.outPoint && !(outPoint < other.outPoint);
}

bool CClaimValue::operator==(const CClaimValue& other) const
{
    return outPoint == other.outPoint && claimId == other.claimId && nAmount == other.nAmount && nHeight == other.nHeight && nValidAtHeight == other.nValidAtHeight;
}

bool CClaimValue::operator!=(const CClaimValue& other) const
{
    return !(*this == other);
}

std::string CClaimValue::ToString() const
{
    std::stringstream ss;
    ss  << "CClaimValue(" << outPoint.ToString()
        << ", " << claimId.ToString()
        << ", " << nAmount
        << ", " << nEffectiveAmount
        << ", " << nHeight
        << ", " << nValidAtHeight << ')';
    return ss.str();
}

CSupportValue::CSupportValue(CTxOutPoint outPoint, CUint160 supportedClaimId, int64_t nAmount, int nHeight, int nValidAtHeight)
    : outPoint(std::move(outPoint)), supportedClaimId(std::move(supportedClaimId)), nAmount(nAmount), nHeight(nHeight), nValidAtHeight(nValidAtHeight)
{
}

bool CSupportValue::operator==(const CSupportValue& other) const
{
    return outPoint == other.outPoint && supportedClaimId == other.supportedClaimId && nAmount == other.nAmount && nHeight == other.nHeight && nValidAtHeight == other.nValidAtHeight;
}

bool CSupportValue::operator!=(const CSupportValue& other) const
{
    return !(*this == other);
}

std::string CSupportValue::ToString() const
{
    std::stringstream ss;
    ss  << "CSupportValue(" << outPoint.ToString()
        << ", " << supportedClaimId.ToString()
        << ", " << nAmount
        << ", " << nHeight
        << ", " << nValidAtHeight << ')';
    return ss.str();
}

bool CClaimTrieData::insertClaim(const CClaimValue& claim)
{
    claims.push_back(claim);
    return true;
}

bool CClaimTrieData::removeClaim(const CTxOutPoint& outPoint, CClaimValue& claim)
{
    if (eraseOutPoint(claims, outPoint, &claim))
        return true;

    logPrint << "CClaimTrieData::" << __func__ << "(): asked to remove a "
             << claim.ToString() << " that doesn't exist" << Clog::endl;
    return false;
}

bool CClaimTrieData::getBestClaim(CClaimValue& claim) const
{
    if (claims.empty())
        return false;
    claim = claims.front();
    return true;
}

bool CClaimTrieData::haveClaim(const CTxOutPoint& outPoint) const
{
    return findOutPoint(claims, outPoint) != claims.end();
}

void CClaimTrieData::reorderClaims(const supportEntryType& supports)
{
    for (auto& claim : claims) {
        claim.nEffectiveAmount = claim.nAmount;
        for (const auto& support : supports)
            if (support.supportedClaimId == claim.claimId)
                claim.nEffectiveAmount += support.nAmount;
    }

    std::sort(claims.rbegin(), claims.rend());
}

bool CClaimTrieData::operator==(const CClaimTrieData& other) const
{
    return hash == other.hash && nHeightOfLastTakeover == other.nHeightOfLastTakeover && claims == other.claims;
}

bool CClaimTrieData::operator!=(const CClaimTrieData& other) const
{
    return !(*this == other);
}

bool CClaimTrieData::empty() const
{
    return claims.empty();
}

CTxOutPointHeightType::CTxOutPointHeightType(CTxOutPoint outPoint, int nHeight)
    : outPoint(std::move(outPoint)), nHeight(nHeight)
{
}

CNameOutPointHeightType::CNameOutPointHeightType(std::string name, CTxOutPoint outPoint, int nHeight)
    : name(std::move(name)), outPoint(std::move(outPoint)), nHeight(nHeight)
{
}

CNameOutPointType::CNameOutPointType(std::string name, CTxOutPoint outPoint)
    : name(std::move(name)), outPoint(std::move(outPoint))
{
}

bool CNameOutPointType::operator==(const CNameOutPointType& other) const
{
    return name == other.name && outPoint == other.outPoint;
}

CClaimIndexElement::CClaimIndexElement(std::string name, CClaimValue claim)
    : name(std::move(name)), claim(std::move(claim))
{
}
