#ifndef SHA1DEVICE_H
#define SHA1DEVICE_H

#include <stdint.h>

__device__ __forceinline__ uint32_t leftRotateSHA1(uint32_t x, uint32_t c)
{
    return (x << c) | (x >> (32 - c));
}

// CUDA SHA-1 for fixed 5-byte input, raw output (no endian swap)
__device__ void deviceSHA1(const char *input, uint32_t *output)
{
    const int inLen = 5;

    uint32_t h[5] = {
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0};

    uint8_t block[64] = {0};
    for (int i = 0; i < inLen; i++)
        block[i] = input[i];
    block[inLen] = 0x80;
    uint64_t bitLen = inLen * 8;
    for (int i = 0; i < 8; i++)
        block[63 - i] = (bitLen >> (i * 8)) & 0xFF;

    uint32_t w[80];
    for (int i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++)
    {
        w[i] = leftRotateSHA1(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

    for (int i = 0; i < 80; i++)
    {
        uint32_t f, k;
        if (i < 20)
        {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        uint32_t temp = leftRotateSHA1(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = leftRotateSHA1(b, 30);
        b = a;
        a = temp;
    }

    output[0] = h[0] + a;
    output[1] = h[1] + b;
    output[2] = h[2] + c;
    output[3] = h[3] + d;
    output[4] = h[4] + e;
}

#endif
