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

# General notes

Sub-keys of type DSA cannot be "[cross-certified](../doc/cross-certify.md)" using GPG 2.2.19.

What is the _key ID_ ? In PGP, most keys are created in such a way so that what is called the "key ID" is equal to the
lower 32 or 64 bits respectively of a key fingerprint. PGP uses key IDs to refer to public keys for a variety of purposes.

You may get the exception "`only SHA1 supported for key checksum calculations`".

Recent versions of PGP and GnuPG can protect the integrity of secret keys with a 20 byte SHA1
hash instead of the older 2 byte (16 bit) checksum used by previous versions of PGP and GnuPG.
This new SHA1 secret key hash is specifed in RFC2440; the simple 16 bit checksum used by most
previous versions of PGP and GPG is now deprecated.  

# Note about the creation of subkeys

A keyring is made of one master key and, optionally, one or more subkeys. 

Keyrings are created using a keyring generator (`org.bouncycastle.openpgp.PGPKeyRingGenerator`).

The question is: can you create a subkey without the use of a keyring generator ?

The technique implemented in this example uses a keyring generator to generate a subkey.

Let's say that:
* we want to generate a subkey for the keyring "KR".
* the master key of the "KR" keyring is "MK".

![](doc/kr-before.svg)

First, we initialize a keyring generator (let's call it "KRG") with 2 key pairs:
* the first key pair is built using "MK".
* the second key pair is generated (using a key pai generator).

Then, we generate a temporary keyring (let's call it "TKR") using the previously created keyring generator ("KRG").
"TKR" contains:
* the master key "MK".
* the new subkey, designed to be added to "KR". Let's call this subkey "SBK".

![](doc/kr-middle.svg)

Finally, we extract "SBK" from "TKR" and we add it to "KR".

![](doc/kr-after.svg)

# Documents

* [java sign public pgp key with bouncycastle](https://stackoverflow.com/questions/28591684/java-sign-public-pgp-key-with-bouncycastle)
* [PGP keys, software security, and much more threatened by new SHA1 exploit](https://arstechnica.com/information-technology/2020/01/pgp-keys-software-security-and-much-more-threatened-by-new-sha1-exploit/)
* [SHA256 RSAkeyPairGenerator #200](https://github.com/bcgit/bc-java/issues/200)
* [GnuPG 2.2.18 released](https://lists.gnupg.org/pipermail/gnupg-devel/2019-November/034487.html)
