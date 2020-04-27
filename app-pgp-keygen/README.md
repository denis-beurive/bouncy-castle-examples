# Description

Illustrates the generation of the PGP keys and key rings.

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)
* [Bouncy Castle OpenPGP API » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk15to18/1.65)

# Documentation

* [RFC 4880](https://tools.ietf.org/html/rfc4880)

# Technical notes

## Run the example

    java -cp "build/libs/app-pgp-keygen-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/bcpg-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/utils-1.0-SNAPSHOT.jar" com.beurive.Main

or

    java -cp "build\libs\app-pgp-keygen-1.0-SNAPSHOT.jar;%PROJECT_ROOT_DIR%\lib\bcprov-jdk15to18-1.65.jar;%PROJECT_ROOT_DIR%\lib\bcpg-jdk15to18-1.65.jar;%PROJECT_ROOT_DIR%\lib\utils-1.0-SNAPSHOT.jar" com.beurive.Main

> Make sure to run `gradle setup` (at the project root level) first.

## Keys structure

Be aware that `PGPPrivateKey` is not identical to `PGPSecretKey`.

The public PGP key structure is defined in the [section 5.5.2 of the RFC 4880](https://tools.ietf.org/html/rfc4880#section-5.5.2).

The private PGP key structure is defined in the [section 5.5.3 of the RFC 4880](https://tools.ietf.org/html/rfc4880#section-5.5.3).

What is the _key ID_ ? In PGP, most keys are created in such a way so that what is called the "key ID" is equal to the
lower 32 or 64 bits respectively of a key fingerprint. PGP uses key IDs to refer to public keys for a variety of purposes.

# Testing the program

**WARNING** To follow the procedure described below, you must not create a DSA sub-key.

    352   PGPKeyPair masterRsaKeyPair = createRsaKeyPair();
    353   // **WARNING**: sub-keys of type DSA cannot be "cross-certified" using GPG 2.2.19.
    354   // If you don't use PGP, then you can create a DSA sub-key:
    355   // PGPKeyPair subKeyPair1 = createDsaKeyPair();
    356   PGPKeyPair subKeyPair1 = createRsaKeyPair();
    357   PGPKeyPair subKeyPair2 = createElGamalKeyPair();

The program produces 3 keys:

    Keys:
                    [FCEC4204265FFBA9] algo=9 (is master ? yes, is signing ? yes)
                    [F71DBD3EF5AC9D45] algo=9 (is master ? no, is signing ? yes)
                    [68DC6B34FEC4F97A] algo=9 (is master ? no, is signing ? no)

# Use the keys

MSDOS:

    SET KEY="FCEC4204265FFBA9"
    
BASH:

    export KEY="FCEC4204265FFBA9"

## Load the keys into the GPG key rings

    $ gpg --import data/secret-keyring.pgp # pass phrase is "password"
    $ gpg --import data/public-keyring.pgp

## Declare the keys into the GPG trust database

    $ gpg --edit-key %KEY%
    -> "trust" [ENTER]
    -> "5" [ENTER]
    -> "o" [ENTER]
    -> "quit"

## Cross certify the keys

    $ gpg --edit-key %KEY%
    -> "cross-certify" [ENTER]
    -> "quit"

## Sign a document

    $ gpg --default-key %KEY%  --output data/signature.sig --sign data/document-to-sign.txt
    $ gpg --default-key %KEY%  --output data/detached-signature.sig --detach-sig data/document-to-sign.txt

## Verify the signatures

    $ gpg --default-key %KEY% --verify data/signature.sig
    $ gpg --default-key %KEY% --verify data/detached-signature.sig data/document-to-sign.txt

# Documents

* [Key structure](https://gnupg.org/faq/subkey-cross-certify.html)
* [Why does a secret key have a <ultimate> uid ?](https://unix.stackexchange.com/questions/407062/gpg-list-keys-command-outputs-uid-unknown-after-importing-private-key-onto)
* [Signing Subkey Cross-Certification](https://gnupg.org/faq/subkey-cross-certify.html)
* [java sign public pgp key with bouncycastle](https://stackoverflow.com/questions/28591684/java-sign-public-pgp-key-with-bouncycastle)
* [Cross-certification](doc/cross-certify.md)
* [PGP keys, software security, and much more threatened by new SHA1 exploit](https://arstechnica.com/information-technology/2020/01/pgp-keys-software-security-and-much-more-threatened-by-new-sha1-exploit/)
* [SHA256 RSAkeyPairGenerator #200](https://github.com/bcgit/bc-java/issues/200)
* [GnuPG 2.2.18 released](https://lists.gnupg.org/pipermail/gnupg-devel/2019-November/034487.html)
* [How do you create OpenPGP subkeys with Bouncy Castle API?](http://quabr.com/34694785/how-do-you-create-openpgp-subkeys-with-bouncy-castle-api)
* [Spongycastle](https://github.com/farewell4574/farewell/blob/master/open-keychain-development/extern/spongycastle/pg/src/main/java/org/spongycastle/openpgp/PGPPublicKey.java)
* [Is there a size restriction on signatures in Java (java.security)?](https://stackoverflow.com/questions/2678138/is-there-a-size-restriction-on-signatures-in-java-java-security)
