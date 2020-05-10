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

**WARNING**: sub-keys of type DSA cannot be "[cross-certified](../doc/cross-certify.md)" using GPG 2.2.19.

# Description

* `dumpKeyRing`: dump a keyring into a file.
* `extractPrivateKey`: extract the private key from a secret key.
* `dumpPublicKey`: dump a public key into a file.
* `dumpSecretKey`: dump a secret key into a file.
* `dumpAllPublicKeys`: dump all (public) keys from a public keyring.
* `dumpAllSecretKeys`: dump all (secret) keys from a secret keyring.
* `createRsaKeyPair`: create an RSA key pair.
* `createDsaKeyPair`: create a DSA key pair.
* `createElGamalKeyPair`: create an El Gamal key pair.
* `getKeyRingGenerator`: create a key generator.
* `getSecretKeyIds`: returns all the key IDs from a secret keyring.
* `signKey`: sign a secret key (inludes subpackets).
* `addSubKey`: add a subkey to a keyring.

# Documents

* [Key structure](https://gnupg.org/faq/subkey-cross-certify.html)
* [Why does a secret key have a <ultimate> uid ?](https://unix.stackexchange.com/questions/407062/gpg-list-keys-command-outputs-uid-unknown-after-importing-private-key-onto)
* [Signing Subkey Cross-Certification](https://gnupg.org/faq/subkey-cross-certify.html)
* [java sign public pgp key with bouncycastle](https://stackoverflow.com/questions/28591684/java-sign-public-pgp-key-with-bouncycastle)
* [Cross-certification](../doc/cross-certify.md)
* [PGP keys, software security, and much more threatened by new SHA1 exploit](https://arstechnica.com/information-technology/2020/01/pgp-keys-software-security-and-much-more-threatened-by-new-sha1-exploit/)
* [SHA256 RSAkeyPairGenerator #200](https://github.com/bcgit/bc-java/issues/200)
* [GnuPG 2.2.18 released](https://lists.gnupg.org/pipermail/gnupg-devel/2019-November/034487.html)
* [Is there a size restriction on signatures in Java (java.security)?](https://stackoverflow.com/questions/2678138/is-there-a-size-restriction-on-signatures-in-java-java-security)
