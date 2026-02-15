// QuickXorHash.h
// High-performance C++ implementation of Microsoft's QuickXorHash algorithm.
// Used by OneDrive for Business / SharePoint for file fingerprinting.
//
// Based on the optimized approach from namazso (BSD Zero Clause License)
// and the rclone Go port. Algorithm spec:
// https://docs.microsoft.com/en-us/onedrive/developer/code-snippets/quickxorhash
//
// Integration: Add to 7z CTEnhanced mode to compute hashes during archive
// creation, eliminating the need for Python-side post-processing.

#ifndef QUICK_XOR_HASH_H
#define QUICK_XOR_HASH_H

#pragma warning(disable : 4996)


#include <cstdint>
#include <cstring>
#include <string>

#include "../../../../C/CpuArch.h"

#if defined(__SSE2__) \
    || defined(MY_CPU_AMD64) \
    || (defined(MY_CPU_X86) && defined(_MSC_VER) && _MSC_VER > 1200)
#define Z7_QXH_USE_SSE2
#include <emmintrin.h>
#endif

class CQuickXorHash
{
private:
    uint8_t* _entryBuf;
    size_t _entryBufAlloc;   // allocated size
    size_t _entryBufLen;     // high water mark
    size_t _entryBufPos;     // write cursor
    bool _buffering;

public:
    void StartBuffering()
    {
        _entryBufPos = 0;
        _entryBufLen = 0;
        _buffering = true;
    }

    void AddToBuffer(const uint8_t* data, size_t len)
    {
        if (!_active)
            return;

        size_t needed = _entryBufPos + len;
        if (needed > _entryBufAlloc)
        {
            size_t newAlloc = _entryBufAlloc ? _entryBufAlloc : (1 << 22) + (1 << 20); // 5 MB initial
            while (newAlloc < needed)
                newAlloc <<= 1;
            uint8_t* newBuf = new uint8_t[newAlloc];
            if (_entryBuf && _entryBufLen > 0)
                memcpy(newBuf, _entryBuf, _entryBufLen);
            delete[] _entryBuf;
            _entryBuf = newBuf;
            _entryBufAlloc = newAlloc;
        }

        memcpy(_entryBuf + _entryBufPos, data, len);
        _entryBufPos += len;
        if (_entryBufPos > _entryBufLen)
            _entryBufLen = _entryBufPos;
    }

    void RewindBuffer()
    {
        _entryBufPos = 0;
    }

    void FlushBuffer()
    {
        if (_entryBufLen > 0)
            Update(_entryBuf, _entryBufLen);
        _entryBufPos = 0;
        _entryBufLen = 0;
        _buffering = false;
    }

    bool IsBuffering() const { return _buffering; }
public:
    static const int kHashSize = 20;          // 160 bits output
    static const int kShift = 11;
    static const int kWidthInBits = kHashSize * 8;  // 160
    static const int kDataSize = kShift * kWidthInBits;  // 1760 bytes accumulator

    CQuickXorHash()
    {
        _debugFile = NULL;
        _active = true;
        _entryBuf = NULL;
        _entryBufAlloc = 0;
        _entryBufLen = 0;
        _entryBufPos = 0;
        _buffering = false;
        Reset();
    }

    ~CQuickXorHash()
    {
        CloseDebugDump();
        delete[] _entryBuf;
    }

    bool IsActive() const { return _active; };

    void SetActive(bool active) { _active = active; }

    void EnableDebugDump(const char* path)
    {
        if (_debugFile)
            fclose(_debugFile);
        _debugFile = fopen(path, "wb");
    }

    void CloseDebugDump()
    {
        if (_debugFile)
        {
            fclose(_debugFile);
            _debugFile = NULL;
        }
    }

    void Reset()
    {
        memset(_data, 0, sizeof(_data));
        _size = 0;
    }

    void Update(const uint8_t *buf, size_t len)
    {
        if (!_active) {
            return;
        }

        if (_debugFile)
            fwrite(buf, 1, len, _debugFile);

        // XOR input bytes into the circular accumulator.
        // The accumulator is 1760 bytes; input is XORed at position (_size % 1760).
        // When the input is larger than the remaining space, we split across
        // the boundary and continue from the start.

        size_t pos = static_cast<size_t>(_size % kDataSize);
        size_t i = 0;

        // Fill remainder of current position in accumulator
        if (pos != 0)
        {
            size_t remaining = kDataSize - pos;
            size_t n = (len < remaining) ? len : remaining;
            XorBytes(_data + pos, buf, n);
            i += n;
        }

        // XOR full accumulator-sized blocks
        while (len - i >= static_cast<size_t>(kDataSize))
        {
            XorBytes(_data, buf + i, kDataSize);
            i += kDataSize;
        }

        // XOR remaining bytes from the start of accumulator
        if (i < len)
        {
            XorBytes(_data, buf + i, len - i);
        }

        _size += len;
    }

    // Finalize and write the 20-byte hash into `out`.
    // `out` must point to at least kHashSize (20) bytes.
    // Does not modify internal state (can be called multiple times).
    void Finalize(uint8_t *out) const
    {
        // Fold the 1760-byte accumulator into 160 bits (20 bytes) using
        // the circular bit-shift pattern: each byte i of the accumulator
        // is shifted left by (i * 11) % 160 bits before XOR into the result.
        //
        // Since the shift is at the bit level, each accumulator byte may
        // straddle two output bytes.

        uint8_t h[kHashSize + 1];  // 21 bytes: extra byte for overflow
        memset(h, 0, sizeof(h));

        for (int i = 0; i < kDataSize; i++)
        {
            int shift = (i * kShift) % kWidthInBits;
            int shiftBytes = shift / 8;
            int shiftBits = shift % 8;
            int shifted = static_cast<int>(_data[i]) << shiftBits;
            h[shiftBytes] ^= static_cast<uint8_t>(shifted);
            h[shiftBytes + 1] ^= static_cast<uint8_t>(shifted >> 8);
        }

        // The 21st byte (index 20) overflows back to byte 0
        h[0] ^= h[kHashSize];

        // XOR file length (little-endian uint64) into the last 8 bytes
        uint64_t len = _size;
        for (int i = 0; i < 8; i++)
        {
            h[kHashSize - 8 + i] ^= static_cast<uint8_t>(len >> (8 * i));
        }

        memcpy(out, h, kHashSize);
    }

    // Convenience: return hash as base64-encoded string
    std::string GetBase64Digest() const
    {
        uint8_t hash[kHashSize];
        Finalize(hash);
        return Base64Encode(hash, kHashSize);
    }

    // Convenience: return hash as hex string
    std::string GetHexDigest() const
    {
        uint8_t hash[kHashSize];
        Finalize(hash);
        return HexEncode(hash, kHashSize);
    }

    uint64_t GetSize() const { return _size; }

private:
    uint8_t _data[kDataSize];   // 1760-byte circular accumulator
    uint64_t _size;             // total bytes hashed
    FILE* _debugFile;
    bool _active;

    static void XorBytes(uint8_t* dst, const uint8_t* src, size_t len)
    {
        size_t i = 0;

#ifdef Z7_QXH_USE_SSE2
        for (; i + 16 <= len; i += 16)
        {
            __m128i d = _mm_loadu_si128((const __m128i*)(dst + i));
            __m128i s = _mm_loadu_si128((const __m128i*)(src + i));
            _mm_storeu_si128((__m128i*)(dst + i), _mm_xor_si128(d, s));
        }
#endif

        for (; i + 8 <= len; i += 8)
            *(uint64_t*)(dst + i) ^= *(const uint64_t*)(src + i);

        for (; i < len; i++)
            dst[i] ^= src[i];
    }

    static std::string Base64Encode(const uint8_t *data, size_t len)
    {
        static const char table[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        std::string result;
        result.reserve(((len + 2) / 3) * 4);

        for (size_t i = 0; i < len; i += 3)
        {
            uint32_t n = static_cast<uint32_t>(data[i]) << 16;
            if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
            if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);

            result += table[(n >> 18) & 0x3F];
            result += table[(n >> 12) & 0x3F];
            result += (i + 1 < len) ? table[(n >> 6) & 0x3F] : '=';
            result += (i + 2 < len) ? table[n & 0x3F] : '=';
        }
        return result;
    }

    static std::string HexEncode(const uint8_t *data, size_t len)
    {
        static const char hex[] = "0123456789abcdef";
        std::string result;
        result.reserve(len * 2);
        for (size_t i = 0; i < len; i++)
        {
            result += hex[data[i] >> 4];
            result += hex[data[i] & 0x0F];
        }
        return result;
    }
};

#endif // QUICK_XOR_HASH_H
