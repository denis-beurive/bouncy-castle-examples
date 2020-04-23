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

Dump the PGP public keys:

    gpg --list-packets --verbose public-key-1.pgp
    gpg --list-packets --verbose public-key-2.pgp
    gpg --list-packets --verbose public-key-3.pgp

Dump the PGP secret keys:

    gpg --list-packets --verbose secret-key-1.pgp
    gpg --list-packets --verbose secret-key-2.pgp
    gpg --list-packets --verbose secret-key-3.pgp

Dump the PGP key rings:

    gpg --list-packets --verbose public-keyring.pgp
    gpg --list-packets --verbose secret-keyring.pgp

# Documentation

* [Key structure](https://gnupg.org/faq/subkey-cross-certify.html)
* [Why does a secret key have a <ultimate> uid ?](https://unix.stackexchange.com/questions/407062/gpg-list-keys-command-outputs-uid-unknown-after-importing-private-key-onto)
* [Signing Subkey Cross-Certification](https://gnupg.org/faq/subkey-cross-certify.html)
* [java sign public pgp key with bouncycastle](https://stackoverflow.com/questions/28591684/java-sign-public-pgp-key-with-bouncycastle)
