# Description

This repository contains sample programs for the [Bouncy Castle](https://www.bouncycastle.org) library.

# Requirements

You need:
* [OpenJDK14](doc/java-version.md).
* [Gradle 6.3](doc/gradle-version.md).

# OPTIONAL: Using Bouncy Castle BETA version

If you want to use a BETA version of Bouncy Castle, then follow these 2 steps:

* edit the file `build.gradle` and set the project property `USE_BC_BETA` to `true`: `project.ext.set("USE_BC_BETA", true)`.
* download the JAR files that contain the BC BETA version into the directory `local-lib`.
  BC BETA versions can be downloaded from [this URL](https://downloads.bouncycastle.org/betas/).
  For example, you can download `bcpg-jdk15on-166b07.jar` and `bcprov-jdk15on-166b07.jar` from [this URL](https://downloads.bouncycastle.org/betas/)
  and put these files into the local directory `local-lib`.
* you should delete all BC JAR files from the Gradle cache (just to be sure...).
  Under Windows, the Gradle cache is located here: `%HOMEPATH%\.gradle\caches`.
  Under Unix, it is located here: `${HOME}\.gradle\caches`.
* you should also delete all BC JAR files under the directory `lib` (just to be sure...).

> Please note that there is probably a more elegant/better way to handle the use of BETA versions.
> If you know, please let me know.

# Build

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
* [PGP signature types](doc/pgp-sig.md)
* [PGP web of trust](doc/pgp-web-of-trust.md)
* [Cross-certification](doc/cross-certify.md)
* [PGP signature subpackets](doc/pgp-sig-subpacket.md)
* [PGP subkey](doc/pgp-subkey.md)
* [GPG commands](doc/gpg.md)

On the WEB

* [RFC 1991](https://www.ietf.org/rfc/rfc1991.txt)
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

# Notes about Gradle

* Path to the Gradle cache under Windows 10: `%HOMEPATH%\.gradle\caches`
* [Experimenting with Gradle dependencies](https://alexfu.github.io/android/2017/11/07/experimenting-with-gradle-dependencies.html)
* [Declare dependencies as JAR files](https://docs.gradle.org/current/dsl/org.gradle.api.artifacts.dsl.DependencyHandler.html)
