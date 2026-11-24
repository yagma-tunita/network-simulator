#include "Sha.hpp"
#include <cstddef>

namespace
{
    uint32_t Rotl(uint32_t x, int n)
    {
        return (x << n) | (x >> (32 - n));
    }

    uint32_t Rotr(uint32_t x, int n)
    {
        return (x >> n) | (x << (32 - n));
    }

    std::vector<uint8_t> Pad(const std::vector<uint8_t> &data, bool sha256)
    {
        std::vector<uint8_t> msg = data;
        uint64_t bits = uint64_t(data.size()) * 8;
        msg.push_back(0x80);
        while(msg.size() % 64 != 56)
            msg.push_back(0);
        int n = sha256 ? 8 : 8;
        for(int i = n - 1; i >= 0; --i)
            msg.push_back(uint8_t(bits >> (8 * i)));
        return msg;
    }
}

std::array<uint8_t, 20> Sha1(const std::vector<uint8_t> &data)
{
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xefcdab89;
    uint32_t h2 = 0x98badcfe;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xc3d2e1f0;

    std::vector<uint8_t> msg = Pad(data, false);
    for(std::size_t off = 0; off < msg.size(); off += 64)
    {
        uint32_t w[80];
        for(int i = 0; i < 16; ++i)
            w[i] = (uint32_t(msg[off + i * 4]) << 24) |
                   (uint32_t(msg[off + i * 4 + 1]) << 16) |
                   (uint32_t(msg[off + i * 4 + 2]) << 8) |
                   uint32_t(msg[off + i * 4 + 3]);
        for(int i = 16; i < 80; ++i)
            w[i] = Rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for(int i = 0; i < 80; ++i)
        {
            uint32_t f, k;
            if(i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
            else if(i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
            else if(i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
            else { f = b ^ c ^ d; k = 0xca62c1d6; }
            uint32_t tmp = Rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = Rotl(b, 30);
            b = a;
            a = tmp;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    std::array<uint8_t, 20> out{};
    uint32_t h[5] = { h0, h1, h2, h3, h4 };
    for(int i = 0; i < 5; ++i)
        for(int j = 0; j < 4; ++j)
            out[i * 4 + j] = uint8_t(h[i] >> (24 - 8 * j));
    return out;
}

std::array<uint8_t, 32> Sha256(const std::vector<uint8_t> &data)
{
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    std::vector<uint8_t> msg = Pad(data, true);
    for(std::size_t off = 0; off < msg.size(); off += 64)
    {
        uint32_t w[64];
        for(int i = 0; i < 16; ++i)
            w[i] = (uint32_t(msg[off + i * 4]) << 24) |
                   (uint32_t(msg[off + i * 4 + 1]) << 16) |
                   (uint32_t(msg[off + i * 4 + 2]) << 8) |
                   uint32_t(msg[off + i * 4 + 3]);
        for(int i = 16; i < 64; ++i)
        {
            uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for(int i = 0; i < 64; ++i)
        {
            uint32_t S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + S1 + ch + K[i] + w[i];
            uint32_t S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    std::array<uint8_t, 32> out{};
    uint32_t hs[8] = { h0, h1, h2, h3, h4, h5, h6, h7 };
    for(int i = 0; i < 8; ++i)
        for(int j = 0; j < 4; ++j)
            out[i * 4 + j] = uint8_t(hs[i] >> (24 - 8 * j));
    return out;
}
