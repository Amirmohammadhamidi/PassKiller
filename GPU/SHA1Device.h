#ifndef SHA1DEVICE_H
#define SHA1DEVICE_H

#include <stdint.h>

__device__ inline uint32_t leftRotateSHA1(uint32_t x, uint32_t c)
{
    return (x << c) | (x >> (32 - c));
}

// Optimized __device__ SHA1: outputs raw 32-bit hash as uint32_t[5].
__device__ void deviceSHA1(const char *input, uint32_t *output)
{
    const int inLen = 5; // fixed candidate length

    // Initial SHA1 state
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    // Prepare padded message block
    uint8_t block[64] = {0};
#pragma unroll
    for (int i = 0; i < inLen; i++)
    {
        block[i] = input[i];
    }
    block[inLen] = 0x80; // SHA-1 padding

    // Append 64-bit big-endian message length (in bits)
    uint64_t bitLen = inLen * 8;
#pragma unroll
    for (int i = 0; i < 8; i++)
    {
        block[63 - i] = (bitLen >> (i * 8)) & 0xFF;
    }

    // Break block into sixteen 32-bit big-endian words
    uint32_t w[80];
#pragma unroll
    for (int i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }

    // Extend to 80 words
#pragma unroll
    for (int i = 16; i < 80; i++)
    {
        w[i] = leftRotateSHA1(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    // Initialize working vars
    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;

    // Main loop
#pragma unroll
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

    // Final hash = initial + round results
    output[0] = h0 + a;
    output[1] = h1 + b;
    output[2] = h2 + c;
    output[3] = h3 + d;
    output[4] = h4 + e;
}

#endif // SHA1DEVICE_H
