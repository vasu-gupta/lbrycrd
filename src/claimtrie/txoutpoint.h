
#ifndef CLAIMTRIE_TXOUTPUT_H
#define CLAIMTRIE_TXOUTPUT_H

#include <claimtrie/uints.h>

#include <algorithm>
#include <type_traits>
#include <vector>
#include <utility>

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class CTxOutPoint
{
public:
    CUint256 hash;
    uint32_t n = uint32_t(-1);

    CTxOutPoint() = default;
    CTxOutPoint(CTxOutPoint&&) = default;
    CTxOutPoint(const CTxOutPoint&) = default;
    CTxOutPoint(CUint256 hashIn, uint32_t nIn);

    CTxOutPoint& operator=(CTxOutPoint&&) = default;
    CTxOutPoint& operator=(const CTxOutPoint&) = default;

    void SetNull();
    bool IsNull() const;

    friend bool operator<(const CTxOutPoint& a, const CTxOutPoint& b);
    friend bool operator==(const CTxOutPoint& a, const CTxOutPoint& b);
    friend bool operator!=(const CTxOutPoint& a, const CTxOutPoint& b);

    std::string ToString() const;
};

template <typename T>
bool equals(const T& lhs, const T& rhs)
{
    return lhs == rhs;
}

template <typename T>
bool equals(const T& value, const CTxOutPoint& outPoint)
{
    return value.outPoint == outPoint;
}

template <typename T, typename C>
auto findOutPoint(T& cont, const C& point) -> decltype(cont.begin())
{
    using type = typename T::value_type;
    static_assert(std::is_same<typename std::decay<T>::type, std::vector<type>>::value, "T should be a vector type");
    return std::find_if(cont.begin(), cont.end(), [&point](const type& val) {
        return equals(val, point);
    });
}

template <typename T, typename C>
bool eraseOutPoint(std::vector<T>& cont, const C& point, T* value = nullptr)
{
    auto it = findOutPoint(cont, point);
    if (it == cont.end())
        return false;
    if (value)
        std::swap(*it, *value);
    cont.erase(it);
    return true;
}

#endif // CLAIMTRIE_TXOUTPUT_H
