
%module libclaimtrie
%{
#include "uints.h"
#include "txoutpoint.h"
#include "data.h"
#include "prefixtrie.h"
#include "trie.h"
#include "forks.h"
%}

%feature("directors", 1);
%feature("flatnested", 1);

%include stl.i
%include stdint.i
%include std_set.i
%include std_pair.i

%ignore Iterator(Iterator&&);
%ignore CBaseBlob(CBaseBlob &&);
%ignore CPrefixTrie::Iterator::operator->;
%ignore Iterator(const std::string&, const std::shared_ptr<Node>&);
%ignore CClaimIndexElement(CClaimIndexElement &&);
%ignore CClaimNsupports(CClaimNsupports &&);
%ignore CClaimTrieData(CClaimTrieData &&);
%ignore CClaimTrieProof(CClaimTrieProof &&);
%ignore CClaimTrieProofNode(CClaimTrieProofNode &&);
%ignore CClaimValue(CClaimValue &&);
%ignore CSupportValue(CSupportValue &&);
%ignore CTxOutPoint(CTxOutPoint &&);

#define SWIG_INTERFACE

%include "uints.h"
%include "txoutpoint.h"
%include "data.h"
%include "prefixtrie.h"

%template(insert) CPrefixTrie::insert<CClaimTrieData>;
%rename(preInc) CPrefixTrie::Iterator::operator++;
%rename(postInc) CPrefixTrie::Iterator::operator++(int);
%template(iterator) CPrefixTrie::Iterator<false>;
%template(const_iterator) CPrefixTrie::Iterator<true>;
%template(Trie) CPrefixTrie<std::string, CClaimTrieData>;

%include "trie.h"
%include "forks.h"

%template(iteratorVec) std::vector<CClaimTrie::iterator>;
%template(const_iteratorVec) std::vector<CClaimTrie::const_iterator>;

%template(CUint160) CBaseBlob<160>;
%template(CUint256) CBaseBlob<256>;
%template(uint8vec) std::vector<uint8_t>;

%template(claimEntryType) std::vector<CClaimValue>;
%template(supportEntryType) std::vector<CSupportValue>;
%template(claimsNsupports) std::vector<CClaimNsupports>;

%template(proofPair) std::pair<bool, CUint256>;
%template(proofNodePair) std::pair<unsigned char, CUint256>;
%template(nameClaimPair) std::pair<std::string, CClaimValue>;
%template(nameSupportPair) std::pair<std::string, CSupportValue>;
%template(takeoverHeightUndoPair) std::pair<std::string, int>;

%template(proofNodes) std::vector<CClaimTrieProofNode>;
%template(proofPairs) std::vector<std::pair<bool, CUint256>>;
%template(proofNodeChildren) std::vector<std::pair<unsigned char, CUint256>>;
%template(claimQueueRowType) std::vector<nameClaimPair>;
%template(claimQueueType) std::map<int, claimQueueRowType>;
%template(supportQueueRowType) std::vector<nameSupportPair>;
%template(supportQueueType) std::map<int, supportQueueRowType>;
%template(queueNameRowType) std::vector<CTxOutPointHeightType>;
%template(queueNameType) std::map<std::string, queueNameRowType>;
%template(insertUndoType) std::vector<CNameOutPointHeightType>;
%template(expirationQueueRowType) std::vector<CNameOutPointType>;
%template(expirationQueueType) std::map<int, expirationQueueRowType>;
%template(claimIndexClaimListType) std::set<CClaimValue>;
%template(claimIndexElementListType) std::vector<CClaimIndexElement>;
%template(takeoverHeightUndoType) std::vector<std::pair<std::string, int>>;

%rename(CClaimTrieCache) CClaimTrieCacheHashFork;
