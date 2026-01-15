#ifndef CT_ENHANCED_DEFS_H
#define CT_ENHANCED_DEFS_H

#include "../../../Common/MyString.h"
#include "../../../Common/MyTypes.h"

// CT Enhanced Zip extra field size (15 bytes of data)
const unsigned k_CtEnhancedExtra_Size = 15;

// CT Enhanced Zip vendor constants
namespace NCtEnhancedConstants
{
    const UInt16 kVendorVersion = 0x0800;  // 'CT-1'
    const UInt16 kVendorId = 0x5443;       // 'CT'
}

// Block Cipher Algorithm values
namespace NCtCipherAlgorithm
{
    const Byte kAES256 = 0x03;
    const Byte kCamellia256 = 0x13;
    const Byte kSerpent256 = 0x23;  // Reserved
}

// Cipher Mode values
namespace NCtCipherMode
{
    const Byte kCTR = 0x01;
    const Byte kGCM = 0x02;  // Reserved
}

// Key Derivation Scheme values
namespace NCtKdfScheme
{
    const Byte kNull = 0x00;     // Reserved
    const Byte kPBKDF2 = 0x01;
    const Byte kArgon2 = 0x02;   // Reserved
}

// PRF for KDF values
namespace NCtKdfPrf
{
    const Byte kNull = 0x00;         // Reserved
    const Byte kHMAC_SHA256 = 0x01;
    const Byte kHMAC_SHA512 = 0x02;
}

// MAC Algorithm values (must match PRF in v0.6)
namespace NCtMacAlgorithm
{
    const Byte kHMAC_SHA256 = 0x01;
    const Byte kHMAC_SHA512 = 0x02;
}

struct CCtEnhancedZipProps
{
    // Cipher
    Byte CipherAlgorithm;        // 0x03=AES256, 0x13=Camellia256, 0x23=Serpent256
    Byte CipherMode;             // 0x01=CTR, 0x02=GCM

    // KDF
    Byte KdfScheme;              // 0x00=Null, 0x01=PBKDF2, 0x02=Argon2
    Byte KdfPrf;                 // 0x00=Null, 0x01=HMAC-SHA256, 0x02=HMAC-SHA512
    UInt32 KdfIterations;        // Default 5000

    // MAC
    Byte MacAlgorithm;           // 0x01=HMAC-SHA256, 0x02=HMAC-SHA512

    UInt16 Method;               // Compression method, usually Stored, sometimes Deflated.

    // Constructor with defaults
    CCtEnhancedZipProps() :
        CipherAlgorithm(NCtCipherAlgorithm::kAES256),
        CipherMode(NCtCipherMode::kCTR),
        KdfScheme(NCtKdfScheme::kPBKDF2),
        KdfPrf(NCtKdfPrf::kHMAC_SHA256),
        KdfIterations(5000),
        MacAlgorithm(NCtMacAlgorithm::kHMAC_SHA256),
        Method(0)
    {
    }

    AString GetCipherNameAndBits() {
        switch (CipherAlgorithm) {
        case NCtCipherAlgorithm::kAES256:
            return AString("AES-256");
        case NCtCipherAlgorithm::kCamellia256:
            return AString("Camellia-256");
        case NCtCipherAlgorithm::kSerpent256:
            return AString("Serpent-256");
        default:
            return AString("???");
        }
    }

    AString GetMacName() {
        switch (MacAlgorithm) {
        case NCtMacAlgorithm::kHMAC_SHA256:
            return AString("HMAC-SHA-256");
        case NCtMacAlgorithm::kHMAC_SHA512:
            return AString("HMAC-SHA-512");
        default:
            return AString("???");
        }
    }

    // Validation - checks v0.6 constraints
    bool IsValid() const
    {
        // Check v0.6 constraint: MAC must equal KDF PRF
        if (MacAlgorithm != KdfPrf)
            return false;

        // Check supported ciphers
        if (CipherAlgorithm != NCtCipherAlgorithm::kAES256 &&
            CipherAlgorithm != NCtCipherAlgorithm::kCamellia256)
            return false;

        // Check supported modes
        if (CipherMode != NCtCipherMode::kCTR)
            return false;

        // Check supported KDF
        if (KdfScheme != NCtKdfScheme::kPBKDF2)
            return false;

        if (MacAlgorithm != NCtMacAlgorithm::kHMAC_SHA256 &&
            MacAlgorithm != NCtMacAlgorithm::kHMAC_SHA512)
            return false;

        return true;
    }

    // Get salt size based on cipher (all supported ciphers use 16 bytes)
    size_t GetSaltSize() const
    {
        return 16;  // 16 bytes for all supported ciphers
    }

    // Get MAC size based on algorithm
    size_t GetMacSize() const
    {
        switch (MacAlgorithm)
        {
        case NCtMacAlgorithm::kHMAC_SHA256: return 32;
        case NCtMacAlgorithm::kHMAC_SHA512: return 64;
        default: return 0;
        }
    }

    // Get key size for cipher (all supported ciphers use 256 bits = 32 bytes)
    size_t GetKeySize() const
    {
        return 32;  // 256 bits for all supported ciphers
    }
};

#endif  // #ifndef CT_ENHANCED_DEFS_H
