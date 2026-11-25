#include "Hmac.hpp"
#include "Md5.hpp"
#include "Sha.hpp"
#include <array>

namespace
{
    template <typename Hash>
    std::vector<uint8_t> HmacImpl(const std::vector<uint8_t> &key,
                                  const std::vector<uint8_t> &data,
                                  std::size_t blockSize,
                                  Hash hash)
    {
        std::vector<uint8_t> k = key;
        if(k.size() > blockSize)
            k = hash(k);
        k.resize(blockSize, 0);

        std::vector<uint8_t> ipad(blockSize, 0x36);
        std::vector<uint8_t> opad(blockSize, 0x5c);
        for(std::size_t i = 0; i < blockSize; ++i)
        {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }

        std::vector<uint8_t> inner = ipad;
        inner.insert(inner.end(), data.begin(), data.end());
        std::vector<uint8_t> innerHash = hash(inner);

        std::vector<uint8_t> outer = opad;
        outer.insert(outer.end(), innerHash.begin(), innerHash.end());
        return hash(outer);
    }

    std::vector<uint8_t> HashMd5(const std::vector<uint8_t> &data)
    {
        std::array<uint8_t, 16> h = Md5(data);
        return std::vector<uint8_t>(h.begin(), h.end());
    }

    std::vector<uint8_t> HashSha1(const std::vector<uint8_t> &data)
    {
        std::array<uint8_t, 20> h = Sha1(data);
        return std::vector<uint8_t>(h.begin(), h.end());
    }

    std::vector<uint8_t> HashSha256(const std::vector<uint8_t> &data)
    {
        std::array<uint8_t, 32> h = Sha256(data);
        return std::vector<uint8_t>(h.begin(), h.end());
    }
}

std::vector<uint8_t> HmacMd5(const std::vector<uint8_t> &key,
                             const std::vector<uint8_t> &data)
{
    return HmacImpl(key, data, 64, HashMd5);
}

std::vector<uint8_t> HmacSha1(const std::vector<uint8_t> &key,
                              const std::vector<uint8_t> &data)
{
    return HmacImpl(key, data, 64, HashSha1);
}

std::vector<uint8_t> HmacSha256(const std::vector<uint8_t> &key,
                                const std::vector<uint8_t> &data)
{
    return HmacImpl(key, data, 64, HashSha256);
}
