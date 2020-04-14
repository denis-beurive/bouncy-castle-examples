# Description

Illustrates the use of the [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) algorithm using
the [Cipher feedback (FBC) mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)).

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)

# Documentation

* [CFBBlockCipher](https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/crypto/modes/CFBBlockCipher.html)

# Technical notes

## Run the example

    java -cp "build/libs/app-cfb-des-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar" com.beurive.Main

> Make sure to run `gradle setup` (at the project root level) first.

## Cipher algorithm

The DES cipher engine uses blocks whose size is 8 bytes (64 bits).

When using [CBC mode](../app-cbc-des/README.md) with DES, data is encrypted in blocks of 8 bytes.

However, when using CFB mode with DES, it is possible to encrypt data in blocks of any number of bytes.

The size of the blocks is defined during the block cipher instantiation: 

    CFBBlockCipher engine = new CFBBlockCipher(new DESEngine(), 8); 

In the example above, we use blocks of 1 byte (8 bits).
That is: input data is consumed one byte at a time.
Hence, when using CFB mode, padding is not necessary.

* **DES block size**: 64 bits (8 bytes)
* **DES key length**:
  * _effective_ length: 56 bits (7 bytes)
  * _practical_ size: the key is nominally stored or transmitted as **8 bytes**, each with odd parity.
    One bit in each 8-bit byte of the KEY may be utilized for error detection in key generation,
    distribution, and storage. Bits 8, 16,..., 64 are for use in ensuring that each byte is of odd
    parity.
* **CFB block size**: a multiple of 8 bits. Thus: any number of bytes.

In the example, we use:

        byte[] input = Hex.decode("4e6f77206973");
        byte[] key = Hex.decode("0123456789abcdef");
        byte[] iv = Hex.decode("0123456789000000");

The length of the _clear text_ (`input`) is: `6` bytes.
