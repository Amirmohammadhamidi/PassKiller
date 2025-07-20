#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <thread>
#include <atomic>
#include <array>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <mutex>
#include <future>

// ==================== MD5 ====================
class MD5
{
private:
    // define necessery matrices :
    static constexpr std::array<uint32_t, 64> k = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

    static constexpr std::array<uint32_t, 64> s = {
        7, 12, 17, 22, 7, 12, 17, 22,
        7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20,
        5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23,
        4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21,
        6, 10, 15, 21, 6, 10, 15, 21};

    static uint32_t leftRotate(uint32_t x, uint32_t c)
    {
        return (x << c) | (x >> (32 - c));
    }
    static void processBlock(const uint8_t *block, uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d)
    {
        uint32_t w[16];
        for (int i = 0; i < 16; ++i)
        {
            w[i] = (block[i * 4 + 0]) | (block[i * 4 + 1] << 8) | (block[i * 4 + 2] << 16) | (block[i * 4 + 3] << 24);
        }
        uint32_t aa = a, bb = b, cc = c, dd = d;
        for (int i = 0; i < 64; ++i)
        {
            uint32_t f = 0, g = 0;
            if (i < 16)
            {
                f = (b & c) | ((~b) & d);
                g = i;
            }
            else if (i < 32)
            {
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            }
            else if (i < 48)
            {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            }
            else
            {
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }
            uint32_t temp = d;
            d = c;
            c = b;
            b = b + leftRotate(a + f + k[i] + w[g], s[i]);
            a = temp;
            // Debugging output
        }
        a += aa;
        b += bb;
        c += cc;
        d += dd;
    }

public:
    static uint32_t swapEndian(uint32_t n)
    {
        return ((n & 0xFF000000) >> 24) |
               ((n & 0x00FF0000) >> 8) |
               ((n & 0x0000FF00) << 8) |
               ((n & 0x000000FF) << 24);
    }
    static std::string hash(const std::string &input)
    {
        uint32_t a = 0x67452301;
        uint32_t b = 0xefcdab89;
        uint32_t c = 0x98badcfe;
        uint32_t d = 0x10325476;
        uint64_t bitLength = input.size() * 8;
        std::vector<uint8_t> padded(input.begin(), input.end());
        padded.push_back(0x80);
        while ((padded.size() % 64) != 56)
            padded.push_back(0);
        for (int i = 0; i < 8; ++i)
            padded.push_back((bitLength >> (i * 8)) & 0xff);
        for (size_t i = 0; i < padded.size(); i += 64)
            processBlock(&padded[i], a, b, c, d);
        std::ostringstream result;
        result << std::hex << std::setfill('0')
               << std::setw(8) << swapEndian(a)
               << std::setw(8) << swapEndian(b)
               << std::setw(8) << swapEndian(c)
               << std::setw(8) << swapEndian(d);
        return result.str();
    }
};

constexpr std::array<uint32_t, 64> MD5::k;
constexpr std::array<uint32_t, 64> MD5::s;

// ==================== SHA1 ====================
class SHA1
{
private:
    static constexpr std::array<uint32_t, 4> k = {
        0x5A827999, // (0 <= t <= 19)
        0x6ED9EBA1, // (20 <= t <= 39)
        0x8F1BBCDC, // (40 <= t <= 59)
        0xCA62C1D6  // (60 <= t <= 79)
    };

    static uint32_t leftRotate(uint32_t x, uint32_t n)
    {
        return (x << n) | (x >> (32 - n));
    }

    static void processBlock(const uint8_t *block, uint32_t &h0, uint32_t &h1, uint32_t &h2, uint32_t &h3, uint32_t &h4)
    {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
        {
            w[i] = (block[i * 4 + 0] << 24) |
                   (block[i * 4 + 1] << 16) |
                   (block[i * 4 + 2] << 8) |
                   (block[i * 4 + 3]);
        }
        for (int i = 16; i < 80; ++i)
        {
            w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;

        for (int i = 0; i < 80; ++i)
        {
            uint32_t f, kTemp;
            if (i < 20)
            {
                f = (b & c) | ((~b) & d);
                kTemp = k[0];
            }
            else if (i < 40)
            {
                f = b ^ c ^ d;
                kTemp = k[1];
            }
            else if (i < 60)
            {
                f = (b & c) | (b & d) | (c & d);
                kTemp = k[2];
            }
            else
            {
                f = b ^ c ^ d;
                kTemp = k[3];
            }
            uint32_t temp = leftRotate(a, 5) + f + e + kTemp + w[i];
            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

public:
    static std::string hash(const std::string &input)
    {
        uint32_t h0 = 0x67452301;
        uint32_t h1 = 0xEFCDAB89;
        uint32_t h2 = 0x98BADCFE;
        uint32_t h3 = 0x10325476;
        uint32_t h4 = 0xC3D2E1F0;

        uint64_t bitLength = static_cast<uint64_t>(input.size()) * 8;

        std::vector<uint8_t> padded(input.begin(), input.end());
        padded.push_back(0x80);
        while ((padded.size() % 64) != 56)
            padded.push_back(0x00);
        for (int i = 7; i >= 0; --i)
            padded.push_back((bitLength >> (i * 8)) & 0xff);

        for (size_t i = 0; i < padded.size(); i += 64)
            processBlock(&padded[i], h0, h1, h2, h3, h4);

        std::ostringstream result;
        result << std::hex << std::setfill('0')
               << std::setw(8) << h0
               << std::setw(8) << h1
               << std::setw(8) << h2
               << std::setw(8) << h3
               << std::setw(8) << h4;
        return result.str();
    }
};

// ==================== SHA256 ====================

class SHA256
{
private:
    static constexpr std::array<uint32_t, 64> k = {
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
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    static uint32_t rotr(uint32_t x, uint32_t n)
    {
        return (x >> n) | (x << (32 - n));
    }

    static void processBlock(const uint8_t *block, uint32_t *hash)
    {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
        {
            w[i] = (block[i * 4 + 0] << 24) |
                   (block[i * 4 + 1] << 16) |
                   (block[i * 4 + 2] << 8) |
                   (block[i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i)
        {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = hash[0];
        uint32_t b = hash[1];
        uint32_t c = hash[2];
        uint32_t d = hash[3];
        uint32_t e = hash[4];
        uint32_t f = hash[5];
        uint32_t g = hash[6];
        uint32_t h = hash[7];

        for (int i = 0; i < 64; ++i)
        {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

public:
    static std::string hash(const std::string &input)
    {
        uint32_t hash[8] = {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19};

        uint64_t bitLength = static_cast<uint64_t>(input.size()) * 8;
        std::vector<uint8_t> padded(input.begin(), input.end());
        padded.push_back(0x80);
        while ((padded.size() % 64) != 56)
            padded.push_back(0x00);
        for (int i = 7; i >= 0; --i)
            padded.push_back((bitLength >> (i * 8)) & 0xff);

        for (size_t i = 0; i < padded.size(); i += 64)
            processBlock(&padded[i], hash);

        std::ostringstream result;
        result << std::hex << std::setfill('0');
        for (int i = 0; i < 8; ++i)
            result << std::setw(8) << hash[i];

        return result.str();
    }
};

// ==================== SHA512 ====================

class SHA512
{
private:
    static constexpr std::array<uint64_t, 80> k = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

    static uint64_t rotr(uint64_t x, uint64_t n)
    {
        return (x >> n) | (x << (64 - n));
    }

    static void processBlock(const uint8_t *block, uint64_t *hash)
    {
        uint64_t w[80];

        // Convert block to 16 64-bit words (big-endian)
        for (int i = 0; i < 16; ++i)
        {
            w[i] = (static_cast<uint64_t>(block[i * 8 + 0]) << 56) |
                   (static_cast<uint64_t>(block[i * 8 + 1]) << 48) |
                   (static_cast<uint64_t>(block[i * 8 + 2]) << 40) |
                   (static_cast<uint64_t>(block[i * 8 + 3]) << 32) |
                   (static_cast<uint64_t>(block[i * 8 + 4]) << 24) |
                   (static_cast<uint64_t>(block[i * 8 + 5]) << 16) |
                   (static_cast<uint64_t>(block[i * 8 + 6]) << 8) |
                   (static_cast<uint64_t>(block[i * 8 + 7]));
        }

        // Extend the first 16 words into the remaining 64 words
        for (int i = 16; i < 80; ++i)
        {
            uint64_t s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
            uint64_t s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        // Initialize working variables
        uint64_t a = hash[0], b = hash[1], c = hash[2], d = hash[3];
        uint64_t e = hash[4], f = hash[5], g = hash[6], h = hash[7];

        // Compression function main loop
        for (int i = 0; i < 80; ++i)
        {
            uint64_t S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
            uint64_t ch = (e & f) ^ ((~e) & g);
            uint64_t temp1 = h + S1 + ch + k[i] + w[i];
            uint64_t S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Update hash values
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

public:
    static std::string hash(const std::string &input)
    {
        uint64_t hash[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

        // Calculate message length in bits
        uint64_t bitLength = static_cast<uint64_t>(input.size()) * 8;

        // Create padding: original message + 0x80 + zeros + length (128 bits)
        std::vector<uint8_t> padded(input.begin(), input.end());
        padded.push_back(0x80);

        // Pad with zeros until length ≡ 112 mod 128
        while ((padded.size() % 128) != 112)
        {
            padded.push_back(0x00);
        }

        // Append the length in bits as a 128-bit big-endian integer
        for (int i = 15; i >= 8; --i)
        {
            padded.push_back(0x00); // Upper 64 bits of length are zero for messages < 2^64 bits
        }
        for (int i = 7; i >= 0; --i)
        {
            padded.push_back((bitLength >> (i * 8)) & 0xff);
        }

        // Process each 1024-bit (128-byte) block
        for (size_t i = 0; i < padded.size(); i += 128)
        {
            processBlock(&padded[i], hash);
        }

        // Produce the final hash value (big-endian)
        std::ostringstream result;
        result << std::hex << std::setfill('0');
        for (int i = 0; i < 8; ++i)
        {
            result << std::setw(16) << hash[i];
        }
        return result.str();
    }
};

// ==================== Hash Dispatcher ====================

using HashFunc = std::function<std::string(const std::string &)>;

HashFunc getHash(const std::string &type)
{
    static const std::unordered_map<std::string, HashFunc> hash_map = {
        {"md5", &MD5::hash},
        {"sha1", &SHA1::hash},
        {"sha256", &SHA256::hash},
        {"sha512", &SHA512::hash}};

    auto it = hash_map.find(type);
    return (it != hash_map.end()) ? it->second : nullptr;
}

// ==================== Cracker Engine ====================

class HashCrackerEngine
{
private:
    std::string type;

protected:
    std::atomic<bool> isRunning{false};
    std::atomic<bool> passwordFound{false};
    std::string foundPassword;

public:
    virtual ~HashCrackerEngine() = default;
    virtual std::string crack(const std::string &targetHash,
                              const std::string &hashtype,
                              const std::vector<std::string> &wordlist) = 0;

    void initialize()
    {
        isRunning = true;
        passwordFound = false;
        foundPassword.clear();
    }

    void setType(std::string type) { this->type = std::move(type); }
    std::string getType() { return type; }

    void stop() { isRunning = false; }
    bool running() const { return isRunning; }
    std::string result() const { return passwordFound ? foundPassword : ""; }
};

struct PasswordFoundException : public std::exception
{
    const char *what() const noexcept override { return "Password found"; }
};

// ==================== CPUCracker ====================

class CPUCracker : public HashCrackerEngine
{
public:
    std::string crack(const std::string &targetHash,
                      const std::string &hashtype,
                      const std::vector<std::string> & /*unused*/) override
    {
        initialize();
        setType(hashtype);
        const char *charset = "abcdefghijklmnopqrstuvwxyz0123456789";
        auto hashFunc = getHash(hashtype);

        if (!hashFunc)
        {
            std::cerr << "Invalid hash type: " << hashtype << "\n";
            return "";
        }

        try
        {
            generate_combination("", charset, 0, targetHash, hashFunc);
        }
        catch (const PasswordFoundException &)
        {
        }

        return result();
    }

private:
    void generate_combination(const std::string &str, const char *charset, int length,
                              const std::string &targetHash, HashFunc hashFunc)
    {
        if (length > 5 || !running())
            return;

        for (int i = 0; charset[i] != '\0'; ++i)
        {
            std::string new_str = str + charset[i];

            if (hashFunc(new_str) == targetHash)
            {
                passwordFound = true;
                foundPassword = new_str;
                throw PasswordFoundException();
            }

            generate_combination(new_str, charset, length + 1, targetHash, hashFunc);
        }
    }
};