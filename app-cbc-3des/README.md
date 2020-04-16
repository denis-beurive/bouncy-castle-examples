# Description

Illustrates the use of the [3DES](https://en.wikipedia.org/wiki/Triple_DES) algorithm using
the [Cipher block chaining (CBC) mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)).

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)

# Documentation

* [CBCBlockCipher](https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/crypto/modes/CBCBlockCipher.html)

# Technical notes

## Run the example

    java -cp "build/libs/app-cbc-3des-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar" com.beurive.Main

or

    java -cp "build\libs\app-pgp-sign-1.0-SNAPSHOT.jar;%PROJECT_ROOT_DIR%\lib\bcprov-jdk15to18-1.65.jar;%PROJECT_ROOT_DIR%\lib\bcpg-jdk15to18-1.65.jar;%PROJECT_ROOT_DIR%\lib\utils-1.0-SNAPSHOT.jar" com.beurive.Main

> Make sure to run `gradle setup` (at the project root level) first.

## Cipher algorithm

* **3DES block size**: 64 bits (8 bytes)
* **3DES key length**: 16 or 24 bytes
* **3DES IV size**: the same as the 3DES block size (8 bytes)
