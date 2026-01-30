# CircleTech 7-Zip on GitHub
This is a fork of original 7-Zip: [7-zip.org](https://7-zip.org), with 
the added functionality of creating and extracting of CTEnhancedZip archives.

## CTEnhancedZip
A new ZIP format, intended as a more modern and safer alternative to WinZip-AES. Eschews weaker cryptographic primitives (no 128-bit or 192-bit ciphers, no SHA1)
and allows for wider choice of ciphers and MACs.

### Header Structure for Encrypted Files 

Standard header entries, including previous Extra Fields (such as Zip64 Extra Field, if applicable):   
    
    0x33            Extract Zip Spec (5.1)
    0x00            Extract OS       (MS-DOS)
    0x0009          General Purpose Flag (Encryption, Streamed)
    0x70            Compression Method must be set to 112 ('CircleTech Enhanced Encryption')
    0x0000000       Modification Time, always set to binary zeros (so that metadata isn't leaked)
    0x0000000       CRC, always set to binary zeros  
    0x0000000       Compressed Size, always set to binary zeros
    0x0000000       Uncompressed Size, always set to binary zeros
    (fnlen)         Filename Length
    (extralen)      Extra Length
                    Filename
                    (various extras other than CTEnhancedZip)
    0xCEDC          Extra ID for 'CTEnhancedZip'
    0x000F          Length of Extra ID (15 bytes)
    0x0800          Vendor Version, always 0x0800
    0x5443          Vendor ID, always 'CT'
    0x03            Block Cipher. Supported Values: 0x03 = AES-256, 0x13 = Camellia-256
    0x0000          Real Compression Method, any of the supported
    0x01            KDF Scheme. Supported Values: 0x01 = PBKDF2
    0x01            PRF for KDF. Supported Values: 0x01 = HMAC-SHA-256, 0x02 = HMAC-SHA-512
    0x00001388      Iterations for KDF (5000)
    0x01            Auth Code. Supported Values: 0x01 = HMAC-SHA-256, 0x02 = HMAC-SHA-512
    0x01            Cipher Mode. Supported Values: 0x01 = CTR
    (16 bytes)      Cipher Salt, length equal to block size of the cipher, so as of now always 16 bytes
    0xFFFF          Legacy Field (in WinZip-AES, that would be used for fast checking of the password), always 0xFFFF
    PAYLOAD         The actual encrypted payload
    (MAC Code)      The full MAC code of the encrypted payload. 32 bytes for HMAC-SHA-256, 64 bytes for HMAC-SHA-512.

Note that CRC is not used at all. Instead, to check integrity of the payload, MAC is used, which is cryptographically much stronger.

Unlike in WinZip-AES, the MAC isn't truncated and its full length is written into the file. 

Any compatible implementation of CTEnhancedZip MUST support AES-256, Camellia-256, PBKDF2, HMAC-SHA-256, HMAC-SHA-512. As of now, the PRF for KDF and Auth Code SHOULD be identical. 

### Reserved Values for Future Versions

The following values aren't yet supported, but intended to be used in future versions. If you intend to extend this format, DO NOT use these for other algorithms.

| Parameter   | Value | Description                | 
|-------------|-------|----------------------------|
| Cipher      | 0x23  | Serpent-256                |
| KDF         | 0x00  | None (binary key provided) |
| KDF         | 0x02  | Argon2                     |
| Cipher Mode | 0x02  | GCM                        |

## Command-line Arguments

The following CLI arguments enable use of the new format:

| Parameter | Values                                                           | Default     | Description                                                                                                                                           |
|-----------|------------------------------------------------------------------|-------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-mem=`   | CTEnhanced or CT, AES256, AES192, AES128, ZipCrypto              | -           | Encryption method. CT or CTEnhanced create new CTEnhancedZip, AESx creates older WinZip-AES, ZipCrypto creates even older (and very unsafe) standard. |
| `-mec=`   | AES256, AES, Camellia256, Camellia                               | AES256      | Cipher algorithm, CTEnhancedZip only!                                                                                                                 |
| `-mekp=`  | HMAC-SHA256, HMACSHA256, SHA256, HMAC-SHA512, HMACSHA512, SHA512 | HMAC-SHA256 | PRF/MAC algorithm, CTEnhancedZip only!                                                                                                                                   |
| `-meki=`  | Any positive number                                              | 5000        | PBKDF2 iterations, CTEnhancedZip only!                                                                                                                                   |

Unless you intend to use long pseudorandom passwords, the iteration count for PBKDF2 should be higher than the default value of 5000. 

## Performance-Related Info

AES and SHA-256 are usually HW-accelerated on modern CPUs. Camellia and SHA512 are not. Therefore, it can be expected that use of AES-256 and HMAC-SHA-256 is going to be faster.

## How to Build 

### Microsoft Visual Studio on Windows

A file Console.sln is provided, which can be used to build the command-line utility in Debug and Release builds, for 32-bit and 64-bit Windows. Tested under MSVC 2022.

### Clang on Debian Bookworm

This was tested on a standard Debian Bookworm image for Docker.

First, install Clang and ASMC:

    apt-get install clang asmc-linux

Then:
 
    cd CPP/7zip/Bundles/Alone2

and there:

    make DISABLE_RAR=1 -j4 -f ../../cmpl_clang_x64.mak

Makefiles for ASM files have been altered by adding a -c flag to asmc invocation, which resolved the problem with inability to find libasmc.a

This command should build you a version which uses HW acceleration of AES and SHA.
