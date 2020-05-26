# Description

This repository contains sample programs for the [Bouncy Castle](https://www.bouncycastle.org) library.

# Build

You need OpenJDK14.

    $ java -version
    openjdk version "14" 2020-03-17
    OpenJDK Runtime Environment (build 14+36-1461)
    OpenJDK 64-Bit Server VM (build 14+36-1461, mixed mode, sharing)
 
You also need Gradle 6.3.

    ------------------------------------------------------------
    Gradle 6.3
    ------------------------------------------------------------
    
    Build time:   2020-03-24 19:52:07 UTC
    Revision:     bacd40b727b0130eeac8855ae3f9fd9a0b207c60
    
    Kotlin:       1.3.70
    Groovy:       2.5.10
    Ant:          Apache Ant(TM) version 1.10.7 compiled on September 1 2019
    JVM:          14 (Oracle Corporation 14+36-1461)
    OS:           Linux 4.15.0-72-generic amd64

First setup the environment:

    gradle setup
    
* Unix: `. setenv.sh && echo ${PROJECT_ROOT_DIR}`
* DOS: `setenv.bat`
    
Then, build all the example applications:

    gradle build
    
# Examples

## Block ciphers

| Algorithm | Cypher mode | Example                      |
|-----------|-------------|------------------------------|
| DES       | CBC         | [app-cbc-des](app-cbc-des)   |
| DES       | CFB         | [app-cfb-des](app-cfb-des)   |
| DES       | OFB         | [app-ofb-des](app-ofb-des)   |
| AES       | CBC         | [app-cbc-aes](app-cbc-aes)   |
| 3DES      | CBC         | [app-cbc-3des](app-cbc-3des) |

## Hash algorithms

| Algorithm | Example                      |
|-----------|------------------------------|
| SHA256    | [app-sha256](app-sha256)     |
| SHA512    | [app-sha512](app-sha512)     |
| MD5       | [app-md5](app-md5)           |
| Tiger     | [app-tiger](app-tiger)       |

## PGP

| Action               | Example                                        | Notes                                                                              |
|----------------------|------------------------------------------------|------------------------------------------------------------------------------------|
| Key generation       | [app-pgp-keygen](app-pgp-keygen)               | Create and manipulate keyrings                                                     |
| Streams              | [app-streams](app-streams)                     | Armored Input/Output streams, Basic PGP Input/Output streams, JcaPGPObjectFactory  |
| Signing              | [app-pgp-sign](app-pgp-sign)                   | Create and verify signatures                                                       |
| Revocation           | [app-pgp-revocation](app-pgp-revocation)       | Create revocation certificates                                                     |
| Encryption           | [app-pgp-encrypt](app-pgp-encrypt)             | Encrypt a file                                                                     |
| Web of trust         | [app-pgp-web-of-trust](app-pgp-web-of-trust)   | Key signing                                                                        |

# Documents

On this repository:

* [Notes on Bouncy Castle](doc/bouncy-castle-notes.md)
* [PGP packet general anatomy](doc/pgp-packet.md)
* [Anatomy of a secret key keyring](doc/pgp-packets-secret-keyring.md)
* [Anatomy of a signature](doc/pgp-packets-signature.md)
* [Anatomy of a key revocation certificate](doc/pgp-packets-revocation.md)
* [PGP web of trust](doc/pgp-web-of-trust.md)
* [Cross-certification](doc/cross-certify.md)
* [GPG commands](doc/gpg.md)

On the WEB

* [What exactly is a subkey?](https://security.stackexchange.com/questions/76940/what-exactly-is-a-subkey)
* [How are primary key binding signatures (0x19) handled by gpg?](https://lists.gnupg.org/pipermail/gnupg-users/2014-May/049794.html)
* [OpenPGP Under The Hood: literal data](https://under-the-hood.sequoia-pgp.org/literal-data/)
* [Signing Subkey Cross-Certification](https://gnupg.org/faq/subkey-cross-certify.html)
* [Detached signature](https://subversivebytes.wordpress.com/2013/12/10/pgp-cryptography-with-the-legion-of-the-bouncy-castle-part-5/)
* [Why does a secret key have a <ultimate> uid ?](https://unix.stackexchange.com/questions/407062/gpg-list-keys-command-outputs-uid-unknown-after-importing-private-key-onto)
* [Transitioning to a new GPG keypair](https://www.alessandromenti.it/blog/2017/01/transitioning-new-gpg-keypair.html)
* [gen-revoke: extending revocation certificates to subkeys](https://blogs.gentoo.org/mgorny/2019/02/20/gen-revoke-extending-revocation-certificates-to-subkeys/)
* [Bouncy Castle FAQ](http://www.bouncycastle.org/wiki/display/JA1/PGP+Questions)

# Examples from the Bouncy Castle repository

* **File and key manipulation**: [pg/src/main/java/org/bouncycastle/openpgp/examples/PGPExampleUtil.java](https://github.com/bcgit/bc-java/blob/master/pg/src/main/java/org/bouncycastle/openpgp/examples/PGPExampleUtil.java)
* **Encrypt/Decrypt**: [pg/src/main/java/org/bouncycastle/openpgp/examples/KeyBasedFileProcessor.java](https://github.com/bcgit/bc-java/blob/master/pg/src/main/java/org/bouncycastle/openpgp/examples/KeyBasedFileProcessor.java)

