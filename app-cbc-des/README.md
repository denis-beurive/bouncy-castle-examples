# Description

Illustrates the use of the [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) algorithm using
the [Cipher block chaining (CBC) mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)).

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)

# Documentation

* [CBCBlockCipher](https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/crypto/modes/CBCBlockCipher.html)

# Technical notes

## Run the example

    java -cp "build/libs/app-cbc-des-1.0-SNAPSHOT.jar:lib/bcprov-jdk15to18-1.65.jar" com.beurive.Main

> Make sure to run `gradle getDeps` (at the project root level) first.

## Cipher algorithm

* **DES block size**: 64 bits (8 bytes)
* **DES key length**:
  * _effective_ length: 56 bits (7 bytes)
  * _practical_ size: the key is nominally stored or transmitted as **8 bytes**, each with odd parity.
    One bit in each 8-bit byte of the KEY may be utilized for error detection in key generation,
    distribution, and storage. Bits 8, 16,..., 64 are for use in ensuring that each byte is of odd
    parity.
* **DES IV size**: the same as the AES block size (8 bytes).

In the example, we use:

        byte[] input = Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20");
        byte[] key = Hex.decode("0123456789abcdef");
        byte[] iv = Hex.decode("0123456789abcdef");
        
The length of the _clear text_ (`input`) is: `24 = 8 * 3` bytes.
It is, of course, a multiple of 8 (bytes).
