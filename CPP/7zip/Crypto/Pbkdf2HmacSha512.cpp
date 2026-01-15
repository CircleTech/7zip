// Pbkdf2HmacSha512.cpp

#include "StdAfx.h"

#include <string.h>

#include "../../../C/CpuArch.h"

#include "HmacSha512.h"
#include "Pbkdf2HmacSha512.h"

namespace NCrypto {
    namespace NSha512 {

        void Pbkdf2Hmac(const Byte* pwd, size_t pwdSize,
            const Byte* salt, size_t saltSize,
            UInt32 numIterations,
            Byte* key, size_t keySize)
        {
            CHmac baseCtx;
            baseCtx.SetKey(pwd, pwdSize);

            for (UInt32 blockNum = 1; keySize != 0; blockNum++)
            {
                MY_ALIGN(16)
                    Byte u[SHA512_DIGEST_SIZE];
                MY_ALIGN(16)
                    Byte result[SHA512_DIGEST_SIZE];

                // First iteration: HMAC(password, salt || blockNum)
                CHmac ctx = baseCtx;
                ctx.Update(salt, saltSize);

                // Append block number in big-endian
                Byte blockBytes[4];
                blockBytes[0] = (Byte)(blockNum >> 24);
                blockBytes[1] = (Byte)(blockNum >> 16);
                blockBytes[2] = (Byte)(blockNum >> 8);
                blockBytes[3] = (Byte)(blockNum);

                ctx.Update(blockBytes, 4);
                ctx.Final(u);

                // Initialize result with first iteration
                memcpy(result, u, SHA512_DIGEST_SIZE);

                // Remaining iterations: HMAC(password, previous_u) XOR result
                for (UInt32 iter = 1; iter < numIterations; iter++)
                {
                    ctx = baseCtx;
                    ctx.Update(u, SHA512_DIGEST_SIZE);
                    ctx.Final(u);

                    // XOR with accumulated result
                    for (unsigned j = 0; j < SHA512_DIGEST_SIZE; j++)
                        result[j] ^= u[j];
                }

                // Copy to output key buffer
                const unsigned curSize = (keySize < SHA512_DIGEST_SIZE) ? (unsigned)keySize : SHA512_DIGEST_SIZE;
                memcpy(key, result, curSize);
                key += curSize;
                keySize -= curSize;
            }
        }

    }
}
