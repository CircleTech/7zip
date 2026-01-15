// HmacSha512.h
// Implements HMAC-SHA-512 (RFC2104, FIPS-198)

#ifndef ZIP7_INC_CRYPTO_HMAC_SHA512_H
#define ZIP7_INC_CRYPTO_HMAC_SHA512_H

#include "../../../C/Sha512.h"

namespace NCrypto {
	namespace NSha512 {

		const unsigned kBlockSize = SHA512_BLOCK_SIZE;   // 128 bytes
		const unsigned kDigestSize = SHA512_DIGEST_SIZE; // 64 bytes

		class CHmac
		{
			CSha512 _sha;
			CSha512 _sha2;
		public:
			void SetKey(const Byte* key, size_t keySize);
			void Update(const Byte* data, size_t dataSize) { Sha512_Update(&_sha, data, dataSize); }
			void Final(Byte* mac);
		};

	}
}

#endif