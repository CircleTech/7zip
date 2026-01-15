// Crypto/CtCipherCoder.h
/*
This code implements CircleTech Enhanced ZIP (CTEnhanced) encryption format:
  - Cipher: AES-256 or Camellia-256 in CTR mode
  - MAC: HMAC-SHA-256 or HMAC-SHA-512 (full output, not truncated)
  - KDF: PBKDF2 with HMAC-SHA-256 or HMAC-SHA-512 PRF
  - Extra field ID: 0xCEDC (CEDC v0.6)
  - Salt: 16 bytes
  - Legacy field: 2 bytes (0xFF 0xFF)
*/

#ifndef ZIP7_INC_CRYPTO_CT_CIPHER_CODER_H
#define ZIP7_INC_CRYPTO_CT_CIPHER_CODER_H

#include "../../Common/MyBuffer.h"

#include "../IPassword.h"

#include "../Archive/Zip/CtEnhancedDefs.h"
#include "HmacSha256.h"
#include "HmacSha512.h"
#include "MyAes.h"

namespace NCrypto {
    namespace NCtCipherCoder {

        /* CTEnhanced Coder Constants */
        const UInt32 kPasswordSizeMax = 99;
        const unsigned kLegacyFieldSize = 2;   // 0xFF 0xFF

        /* Key Information with Password and Salt */
        struct CKeyInfo
        {
            CCtEnhancedZipProps Props;
            CByteBuffer Password;
            Byte Salt[16];  // Runtime salt storage (16 bytes for all supported ciphers)

            CKeyInfo()
            {
                Z7_memset_0_ARRAY(Salt);
            }

            void Wipe()
            {
                Password.Wipe();
                Z7_memset_0_ARRAY(Salt);
            }

            ~CKeyInfo() { Wipe(); }
        };

        /* Base class for CTEnhanced encryption/decryption */
        class CBaseCoder :
            public ICompressFilter,
            public ICryptoSetPassword,
            public CMyUnknownImp
        {
            Z7_COM_UNKNOWN_IMP_1(ICryptoSetPassword)
                Z7_COM7F_IMP(Init())
        public:
            Z7_IFACE_COM7_IMP(ICryptoSetPassword)
        protected:
            CKeyInfo _key;

            // HMAC context (either SHA-256 or SHA-512)
            CAlignedBuffer _hmacBuf;
            UInt32 _hmacOverCalc;

            // Pointers to HMAC implementation
            NSha256::CHmac* Hmac256() { return (NSha256::CHmac*)(void*)(Byte*)_hmacBuf; }
            NSha512::CHmac* Hmac512() { return (NSha512::CHmac*)(void*)(Byte*)_hmacBuf; }

            // Cipher coder (AES or Camellia in CTR mode)
            CMyComPtr<ICompressFilter> _cipherCoder;

            CBaseCoder();

            void Init2();

        public:
            unsigned GetHeaderSize() const { return (unsigned)_key.Props.GetSaltSize() + kLegacyFieldSize; }
            unsigned GetAddPackSize() const { return GetHeaderSize() + (unsigned)_key.Props.GetMacSize(); }

            // Set encryption properties from extra field
            bool SetProps(const CCtEnhancedZipProps& props)
            {
                if (!props.IsValid())
                    return false;
                _key.Props = props;
                return true;
            }

            virtual ~CBaseCoder() {}
        };

        /* Encoder for creating CTEnhanced archives */
        class CEncoder Z7_final :
            public CBaseCoder
        {
            Z7_COM7F_IMP2(UInt32, Filter(Byte* data, UInt32 size))
        public:
            HRESULT WriteHeader(ISequentialOutStream* outStream);
            HRESULT WriteFooter(ISequentialOutStream* outStream);
        };

        /* Decoder for extracting CTEnhanced archives */
        class CDecoder Z7_final :
            public CBaseCoder
        {
            Byte _legacyFieldFromArchive[kLegacyFieldSize];
            Z7_COM7F_IMP2(UInt32, Filter(Byte* data, UInt32 size))
        public:
            HRESULT ReadHeader(ISequentialInStream* inStream);
            bool Init_and_CheckLegacy();
            HRESULT CheckMac(ISequentialInStream* inStream, bool& isOK);
        };

    }
}

#endif
