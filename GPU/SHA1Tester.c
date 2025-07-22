#include <stdio.h>
#include <stdint.h>
#include <string.h>

// ---------- SHA1 Core ----------

uint32_t leftRotate(uint32_t x, uint32_t c)
{
    return (x << c) | (x >> (32 - c));
}

void sha1_process_block(const uint8_t *block, uint32_t *h)
{
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
        w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
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

        uint32_t temp = leftRotate(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = leftRotate(b, 30);
        b = a;
        a = temp;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

// ---------- Padded SHA1 ----------

void sha1(const char *input, uint32_t *hash_out)
{
    size_t len = strlen(input);
    uint64_t bitLen = len * 8;

    uint8_t padded[128] = {0}; // enough for 1 block + padding
    memcpy(padded, input, len);
    padded[len] = 0x80;

    size_t padLen = ((len + 9) <= 64) ? 64 : 128;
    for (int i = 0; i < 8; ++i)
        padded[padLen - 1 - i] = (bitLen >> (i * 8)) & 0xFF;

    uint32_t h[5] = {
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0};

    for (int i = 0; i < padLen; i += 64)
    {
        sha1_process_block(&padded[i], h);
    }

    for (int i = 0; i < 5; i++)
    {
        hash_out[i] = h[i]; // no endian swap
    }
}

// ---------- Test Main ----------

int main()
{
    const char *testInput = "abcde";
    uint32_t hash[5];
    sha1(testInput, hash);

    printf("SHA-1(\"%s\") = ", testInput);
    for (int i = 0; i < 5; i++)
        printf("%08x", hash[i]);
    printf("\n");

    return 0;
}
