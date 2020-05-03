# Description

Illustrates the use of the streams.

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)
* [Bouncy Castle OpenPGP API » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk15to18/1.65)

# Documentation

* [TigerDigest](https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/crypto/digests/TigerDigest.html)

# Technical notes

## Run the example

    java -cp "build/libs/app-streams-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/bcpg-jdk15to18-1.65.jar" com.beurive.Main

or

    java -cp "build\libs\app-streams-1.0-SNAPSHOT.jar;%PROJECT_ROOT_DIR%\lib\bcprov-jdk15to18-1.65.jar;%PROJECT_ROOT_DIR%\lib\bcpg-jdk15to18-1.65.jar" com.beurive.Main

> Make sure to run `gradle setup` (at the project root level) first.

Result:

    ====================================================
    Input:
    
    This is a text
    
    Armored text:
    
    -----BEGIN PGP MESSAGE-----
    Version: BCPG v1.65
    
    VGhpcyBpcyBhIHRleHQ=
    =oPGh
    -----END PGP MESSAGE-----
    
    ====================================================
    data/secret-keyring.pgp:
        PGPSecretKeyRing:
        PGPSecretKeyRing:
            PGPSecretKey:
                ID: F52712127A58D490
                Is master ley ? yes
                Is signing ley ? yes
                Is empty ? no
                Encryption algorithm: 9
                Is private key empty: no
                S2K usage: 254
                User IDs:
                    User ID: owner@email.com
            PGPSecretKey:
                ID: DF4C6FED0763B6A9
                Is master ley ? no
                Is signing ley ? yes
                Is empty ? no
                Encryption algorithm: 9
                Is private key empty: no
                S2K usage: 254
                User IDs:
            PGPSecretKey:
                ID: 1CAC39B3C005457C
                Is master ley ? no
                Is signing ley ? no
                Is empty ? no
                Encryption algorithm: 9
                Is private key empty: no
                S2K usage: 254
                User IDs:
    ====================================================
    data/detached-signature.pgp:
        PGPSignatureList:
            Number of signatures: 1
            Signatures:
            PGPSignature:
                Version: 4
                Creation time: Wed Apr 29 16:30:55 CEST 2020
                Hash Algorithm: 8
                Key Algorithm: 1
                Key ID: F52712127A58D490
                Type: 0
                Certification ? no
                Has sub packets ? yes
                Has hashed sub-packet count: 2
                    SignatureSubpacket:
                        Type: 2
                        Is critical: no
                        Data length: 4
                    SignatureSubpacket:
                        Type: 28
                        Is critical: no
                        Data length: 15
                Has un-hashed sub-packet count: 1
                    SignatureSubpacket:
                        Type: 16
                        Is critical: no
                        Data length: 8
    ====================================================
    data/document.txt.bpg:
        PGPCompressedData:
            Algorithm: 2
        PGPOnePassSignatureList:
            Is empty: no
            PGPOnePassSignature list:
        PGPOnePassSignatureList:
            Is empty: no
            PGPOnePassSignature list:
            PGPOnePassSignature:
                ID: F52712127A58D490:
                Type: 0:
                Hash algorithm: 2:
                Key algorithm: 1:
                Data length: 15:
        PGPLiteralData:
            Format: 98
            File name: document.txt
            Modification time: Fri May 01 21:53:02 CEST 2020
            Data length: 174
        PGPSignatureList:
            Number of signatures: 1
            Signatures:
            PGPSignature:
                Version: 4
                Creation time: Fri May 01 22:05:01 CEST 2020
                Hash Algorithm: 2
                Key Algorithm: 1
                Key ID: F52712127A58D490
                Type: 0
                Certification ? no
                Has sub packets ? yes
                Has hashed sub-packet count: 2
                    SignatureSubpacket:
                        Type: 2
                        Is critical: no
                        Data length: 4
                    SignatureSubpacket:
                        Type: 28
                        Is critical: no
                        Data length: 15
                Has un-hashed sub-packet count: 1
                    SignatureSubpacket:
                        Type: 16
                        Is critical: no
                        Data length: 8
    ====================================================


