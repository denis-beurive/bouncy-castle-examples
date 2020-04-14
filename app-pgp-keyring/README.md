# Description

Illustrates the keyring management.

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)
* [Bouncy Castle OpenPGP API » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk15to18/1.65)

# Documentation

* [RFC 4880](https://tools.ietf.org/html/rfc4880)

# Technical notes

## Run the example

    java -cp "build/libs/app-pgp-keyring-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/bcpg-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/utils-1.0-SNAPSHOT.jar" com.beurive.Main

> Make sure to run `gradle setup` (at the project root level) first..

The provided example creates key rings with 3 keys:

* A RSA key. This is the master key.
* A DSA key.
* An El Gamal key.

Dump the PGP public key ring:

    gpg --list-packets --verbose public-keyring.pgp
    
Dump the PGP secret key ring:

    gpg --list-packets --verbose secret-keyring.pgp

See the analysis of the [generated documents](../doc/pgp-packets-secret-keyring.md).

