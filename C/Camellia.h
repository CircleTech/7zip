/* camellia.h	ver 1.2.0
 *
 * Copyright (C) 2006,2007
 * NTT (Nippon Telegraph and Telephone Corporation).
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef HEADER_CAMELLIA_H
#define HEADER_CAMELLIA_H

#ifdef  __cplusplus
extern "C" {
#endif

#define CAMELLIA_BLOCK_SIZE 16
#define CAMELLIA_TABLE_BYTE_LEN 272
#define CAMELLIA_TABLE_WORD_LEN (CAMELLIA_TABLE_BYTE_LEN / 4)

	typedef unsigned int KEY_TABLE_TYPE[CAMELLIA_TABLE_WORD_LEN];


	void Camellia_Ekeygen(const int keyBitLength,
		const unsigned char* rawKey,
		KEY_TABLE_TYPE keyTable);

	void Camellia_EncryptBlock(const int keyBitLength,
		const unsigned char* plaintext,
		const KEY_TABLE_TYPE keyTable,
		unsigned char* cipherText);

	void Camellia_DecryptBlock(const int keyBitLength,
		const unsigned char* cipherText,
		const KEY_TABLE_TYPE keyTable,
		unsigned char* plaintext);

	/* ========================================
	 * CTR MODE ADDITIONS - Analogous to AesCtr_Code
	 * ========================================
	 */

	 /* Camellia CTR mode encryption/decryption
	  * p: pointer to state buffer containing:
	  *    [counter (4 x unsigned int = 16 bytes)]
	  *    [keyTable (68 x unsigned int = 272 bytes)]
	  *    Total: 72 x unsigned int = 288 bytes
	  * data: input/output data buffer (modified in place)
	  * numBlocks: number of 16-byte blocks to process
	  *
	  * Usage example:
	  *   unsigned int state[72];  // 4 for counter + 68 for key table
	  *   Camellia_CtrInit(state, key, 256, iv);
	  *   Camellia_CtrCode(state, data, numBlocks);
	  */
	void Camellia_CtrCode(unsigned int* p, unsigned char* data, size_t numBlocks);

	/* Initialize Camellia for CTR mode
	 * p: pointer to state buffer (must be at least CAMELLIA_CTR_STATE_SIZE bytes)
	 * key: encryption key
	 * keyBitLength: key size in bits (128, 192, or 256)
	 * iv: 16-byte initialization vector / initial counter value
	 */
	void Camellia_CtrInit(unsigned int* p, const unsigned char* key,
		int keyBitLength, const unsigned char* iv);

	/* Memory size needed for Camellia CTR state buffer */
#define CAMELLIA_CTR_STATE_SIZE ((4 + CAMELLIA_TABLE_WORD_LEN) * sizeof(unsigned int))


#ifdef  __cplusplus
}
#endif

#endif /* HEADER_CAMELLIA_H */
