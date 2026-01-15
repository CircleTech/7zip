// Crypto/CtCipherCoder.cpp
/*
This code implements CircleTech Enhanced ZIP (CTEnhanced) encryption format.
*/

#include "StdAfx.h"

#include "../../../C/CpuArch.h"
#include "../../../C/Camellia.h"

#include "../Common/StreamUtils.h"

#include "Pbkdf2HmacSha256.h"
#include "Pbkdf2HmacSha512.h"
#include "RandGen.h"
#include "CtCipherCoder.h"

namespace NCrypto {
    namespace NCtCipherCoder {

        /* Helper class for Camellia CTR mode coder */
        class CCamelliaCtrCoder :
            public ICompressFilter,
            public CMyUnknownImp
        {
            Z7_COM_UNKNOWN_IMP_0

                CAlignedBuffer _camellia;
            UInt32* CamelliaState() { return (UInt32*)(Byte*)_camellia; }
            unsigned _keySize;

        public:
            Z7_COM7F_IMP(Init())
                Z7_COM7F_IMP2(UInt32, Filter(Byte* data, UInt32 size))

                CCamelliaCtrCoder(unsigned keySize) :
                _keySize(keySize)
            {
                _camellia.Alloc(CAMELLIA_CTR_STATE_SIZE);
            }

            HRESULT SetKey(const Byte* data, UInt32 size)
            {
                if (size != _keySize)
                    return E_INVALIDARG;

                // Initialize counter to zero (IV will be set later if needed)
                Byte iv[16];
                memset(iv, 0, 16);

                Camellia_CtrInit(CamelliaState(), data, 256, iv);
                return S_OK;
            }
        };

        Z7_COM7F_IMF(CCamelliaCtrCoder::Init())
        {
            // Counter is initialized in SetKey with IV
            return S_OK;
        }

        Z7_COM7F_IMF2(UInt32, CCamelliaCtrCoder::Filter(Byte* data, UInt32 size))
        {
            if (size == 0)
                return 0;

            // Round down to block size
            UInt32 numBlocks = size / CAMELLIA_BLOCK_SIZE;
            if (numBlocks > 0)
            {
                Camellia_CtrCode(CamelliaState(), data, numBlocks);
            }

            return numBlocks * CAMELLIA_BLOCK_SIZE;
        }

        /* CBaseCoder implementation */

        CBaseCoder::CBaseCoder()
        {
            _hmacOverCalc = 0;
        }

        Z7_COM7F_IMF(CBaseCoder::CryptoSetPassword(const Byte* data, UInt32 size))
        {
            if (size > kPasswordSizeMax)
                return E_INVALIDARG;
            _key.Password.Wipe();
            _key.Password.CopyFrom(data, (size_t)size);
            return S_OK;
        }

        void CBaseCoder::Init2()
        {
            _hmacOverCalc = 0;

            const unsigned keySize = (unsigned)_key.Props.GetKeySize();
            const unsigned macSize = (unsigned)_key.Props.GetMacSize();

            // Allocate buffer for HMAC context
            if (_key.Props.MacAlgorithm == NCtMacAlgorithm::kHMAC_SHA512)
            {
                if (!_hmacBuf.IsAllocated())
                    _hmacBuf.Alloc(sizeof(NSha512::CHmac));
            }
            else
            {
                if (!_hmacBuf.IsAllocated())
                    _hmacBuf.Alloc(sizeof(NSha256::CHmac));
            }

            // Derive keys using PBKDF2
            // Output: [encryption key][HMAC key] = total of 2 * keySize
            const unsigned dkSize = 2 * keySize;
            Byte dk[64];  // Max: 2 * 32 = 64 bytes

            if (_key.Props.KdfPrf == NCtKdfPrf::kHMAC_SHA512)
            {
                NSha512::Pbkdf2Hmac(
                    _key.Password, _key.Password.Size(),
                    _key.Salt, _key.Props.GetSaltSize(),
                    _key.Props.KdfIterations,
                    dk, dkSize);
            }
            else  // HMAC-SHA-256
            {
                NSha256::Pbkdf2Hmac(
                    _key.Password, _key.Password.Size(),
                    _key.Salt, _key.Props.GetSaltSize(),
                    _key.Props.KdfIterations,
                    dk, dkSize);
            }

            // Setup HMAC with second half of derived key
            if (_key.Props.MacAlgorithm == NCtMacAlgorithm::kHMAC_SHA512)
            {
                Hmac512()->SetKey(dk + keySize, keySize);
            }
            else
            {
                Hmac256()->SetKey(dk + keySize, keySize);
            }

            _cipherCoder.Release();
            // Setup cipher with first half of derived key            
            if (_key.Props.CipherAlgorithm == NCtCipherAlgorithm::kCamellia256)
            {
                CCamelliaCtrCoder* camelliaCoder = new CCamelliaCtrCoder(keySize);
                _cipherCoder = camelliaCoder;
                if (camelliaCoder->SetKey(dk, keySize) != S_OK)
                    throw 2;
                if (camelliaCoder->Init() != S_OK)
                    throw 3;
            }
            else  // AES-256
            {
                CAesCtrCoder* aesCoder = new CAesCtrCoder(keySize);
                _cipherCoder = aesCoder;
                if (aesCoder->SetKey(dk, keySize) != S_OK)
                    throw 2;
                if (aesCoder->Init() != S_OK)
                    throw 3;
            }

            // Wipe derived key material
            Z7_memset_0_ARRAY(dk);
        }

        Z7_COM7F_IMF(CBaseCoder::Init())
        {
            return S_OK;
        }

        /* CEncoder implementation */

        HRESULT CEncoder::WriteHeader(ISequentialOutStream* outStream)
        {
            const unsigned saltSize = (unsigned)_key.Props.GetSaltSize();

            // Generate random salt
            MY_RAND_GEN(_key.Salt, saltSize);

            // Initialize crypto with salt
            Init2();

            // Write salt
            RINOK(WriteStream(outStream, _key.Salt, saltSize))

                // Write legacy field (0xFF 0xFF)
                Byte legacy[kLegacyFieldSize] = { 0xFF, 0xFF };
            return WriteStream(outStream, legacy, kLegacyFieldSize);
        }

        HRESULT CEncoder::WriteFooter(ISequentialOutStream* outStream)
        {
            const unsigned macSize = (unsigned)_key.Props.GetMacSize();

            // Finalize HMAC
            if (_key.Props.MacAlgorithm == NCtMacAlgorithm::kHMAC_SHA512)
            {
                MY_ALIGN(16)
                    Byte mac[64];
                Hmac512()->Final(mac);
                return WriteStream(outStream, mac, macSize);
            }
            else
            {
                MY_ALIGN(16)
                    Byte mac[32];
                Hmac256()->Final(mac);
                return WriteStream(outStream, mac, macSize);
            }
        }

        Z7_COM7F_IMF2(UInt32, CEncoder::Filter(Byte* data, UInt32 size))
        {
            // Encrypt data
            size = _cipherCoder->Filter(data, size);

            // Update HMAC with encrypted data
            if (_key.Props.MacAlgorithm == NCtMacAlgorithm::kHMAC_SHA512)
                Hmac512()->Update(data, size);
            else
                Hmac256()->Update(data, size);

            return size;
        }

        /* CDecoder implementation */

        HRESULT CDecoder::ReadHeader(ISequentialInStream* inStream)
        {
            const unsigned saltSize = (unsigned)_key.Props.GetSaltSize();

            // Read salt
            RINOK(ReadStream_FAIL(inStream, _key.Salt, saltSize))

                // Read legacy field
                RINOK(ReadStream_FAIL(inStream, _legacyFieldFromArchive, kLegacyFieldSize))

                return S_OK;
        }

        bool CDecoder::Init_and_CheckLegacy()
        {
            Init2();

            // Check legacy field is 0xFF 0xFF
            return (_legacyFieldFromArchive[0] == 0xFF &&
                _legacyFieldFromArchive[1] == 0xFF);
        }

        HRESULT CDecoder::CheckMac(ISequentialInStream* inStream, bool& isOK)
        {
            isOK = false;

            const unsigned macSize = (unsigned)_key.Props.GetMacSize();

            // Read MAC from archive
            MY_ALIGN(16)
                Byte mac1[64];  // Use largest size (SHA-512)
            RINOK(ReadStream_FAIL(inStream, mac1, macSize))

                // Compute MAC
                MY_ALIGN(16)
                Byte mac2[64];  // Use largest size (SHA-512)

            if (_key.Props.MacAlgorithm == NCtMacAlgorithm::kHMAC_SHA512)
            {
                Hmac512()->Final(mac2);
            }
            else
            {
                Hmac256()->Final(mac2);
            }

            // Compare MACs
            isOK = (memcmp(mac1, mac2, macSize) == 0);

            if (_hmacOverCalc)
                isOK = false;

            return S_OK;
        }

        Z7_COM7F_IMF2(UInt32, CDecoder::Filter(Byte* data, UInt32 size))
        {
            // Round down to block size for MAC calculation
            if (size >= 16)
                size &= ~(UInt32)15;

            // Update HMAC with encrypted data before decryption
            if (_hmacOverCalc < size)
            {
                if (_key.Props.MacAlgorithm == NCtMacAlgorithm::kHMAC_SHA512)
                    Hmac512()->Update(data + _hmacOverCalc, size - _hmacOverCalc);
                else
                    Hmac256()->Update(data + _hmacOverCalc, size - _hmacOverCalc);

                _hmacOverCalc = size;
            }

            // Decrypt data
            size = _cipherCoder->Filter(data, size);
            _hmacOverCalc -= size;

            return size;
        }

    }
}