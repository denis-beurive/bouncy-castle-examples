# Description

Illustrates the use of the [3DES](https://en.wikipedia.org/wiki/Triple_DES) algorithm using
the [Cipher block chaining (CBC) mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)).

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)

# Documentation

* [CBCBlockCipher](https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/crypto/modes/CBCBlockCipher.html)

# Technical notes

## Run the example

    export MAIN=build/libs/app-cbc-3des-1.0-SNAPSHOT.jar
    java -cp "${CLASSPATH}:${MAIN}" com.beurive.Main

or

    SET MAIN=build\libs\app-cbc-3des-1.0-SNAPSHOT.jar
    java -cp "%CLASSPATH%;%MAIN%" com.beurive.Main

> **WARNING**
>
> Before you execute one of the commands given ahead, make sure to follow this procedure:
>
> * run `gradle setup` (at the project root level). This will create the files `setup.bat` and `setup.sh`.
> * Depending on the OS:
>   * Windows: execute `setup.bat`.
>   * Unix (linux, Mac...): execute `setup.sh`.
>
> These scripts set the CLASSPATH environment variable.

## Cipher algorithm

* **3DES block size**: 64 bits (8 bytes)
* **3DES key length**: 16 or 24 bytes
* **3DES IV size**: the same as the 3DES block size (8 bytes)
