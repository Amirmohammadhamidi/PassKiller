#ifndef SHA1DEVICE_H
#define SHA1DEVICE_H

#include <stdint.h>

__device__ inline uint32_t leftRotateSHA1(uint32_t x, uint32_t c)
{
    return (x << c) | (x >> (32 - c));
}

__device__ inline uint32_t swapEndianSHA1(uint32_t n)
{
    return ((n >> 24) & 0x000000FF) |
           ((n >> 8) & 0x0000FF00) |
           ((n << 8) & 0x00FF0000) |
           ((n << 24) & 0xFF000000);
}

// CUDA SHA-1 for fixed 5-byte input, outputs endian-swapped uint32_t[5]
__device__ void deviceSHA1(const char *input, uint32_t *output)
{
    const int inLen = 5;

    // Initial state
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    // Prepare 512-bit (64-byte) block
    uint8_t block[64] = {0};
#pragma unroll
    for (int i = 0; i < inLen; i++)
        block[i] = input[i];
    block[inLen] = 0x80; // append '1' bit

    // Set message length in bits at the end (big-endian)
    uint64_t bitLen = inLen * 8;
#pragma unroll
    for (int i = 0; i < 8; i++)
        block[63 - i] = (bitLen >> (i * 8)) & 0xFF;

    // Parse 16 big-endian 32-bit words
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

    // SHA-1 main loop
    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;

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

    // Final state with endian swap for output matching CPU version
    output[0] = swapEndianSHA1(h0 + a);
    output[1] = swapEndianSHA1(h1 + b);
    output[2] = swapEndianSHA1(h2 + c);
    output[3] = swapEndianSHA1(h3 + d);
    output[4] = swapEndianSHA1(h4 + e);
}

#endif // SHA1DEVICE_H
