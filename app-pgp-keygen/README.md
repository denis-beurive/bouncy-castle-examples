# Description

Illustrates the generation of the PGP keys.

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)
* [Bouncy Castle OpenPGP API » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk15to18/1.65)

# Documentation

* [RFC 4880](https://tools.ietf.org/html/rfc4880)
* [RSAKeyGenerationParameters](https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/crypto/params/RSAKeyGenerationParameters.html)

# Technical notes

## Run the example

    java -cp "build/libs/app-pgp-keygen-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/bcpg-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/utils-1.0-SNAPSHOT.jar" com.beurive.Main

> Make sure to run `gradle getDeps` (at the project root level) first.

## Keys structure

Be aware the sample code produces [Key Material Packet](https://tools.ietf.org/html/rfc4880#section-5.5) (see section _5.5_ of the RFC 4880):

> A key material packet contains all the information about a public or
> private key.  There are four variants of this packet type, and two
> major versions.  Consequently, this section is complex.

The public key structure is defined in the [section 5.5.2 of the RFC 4880](https://tools.ietf.org/html/rfc4880#section-5.5.2).

The private key structure is defined in the [section 5.5.3 of the RFC 4880](https://tools.ietf.org/html/rfc4880#section-5.5.3).

> **What is the _key ID_** ? In PGP, most keys are created in such a way so that what is called the "key ID" is equal to the
> lower 32 or 64 bits respectively of a key fingerprint. PGP uses key IDs to refer to public keys for a variety of purposes.

