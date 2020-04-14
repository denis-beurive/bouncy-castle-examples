# Description

Illustrates the use of the [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) algorithm using
the [Cipher block chaining (CBC) mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)).

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)

# Documentation

* [CBCBlockCipher](https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/crypto/modes/CBCBlockCipher.html)

# Technical notes

## Run the example

    java -cp "build/libs/app-cbc-aes-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar" com.beurive.Main

> Make sure to run `gradle setup` (at the project root level) first.

## Cipher algorithm

* **AES block size**: 128 bits
* **AES key length**: 128 bits, 192 bits or 256 bits
* **AES IV size**: the same as the AES block size (128 bits).
