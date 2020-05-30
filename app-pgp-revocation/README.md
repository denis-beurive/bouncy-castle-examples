# Description

Illustrates the creation of revocation certificates.

See [Master/Sub key revocation](../doc/pgp-packets-revocation.md).

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)
* [Bouncy Castle OpenPGP API » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk15to18/1.65)

# Documentation

* [RFC 4880](https://tools.ietf.org/html/rfc4880)

# Technical notes

## Run the example

    export MAIN=build/libs/app-pgp-certification-1.0-SNAPSHOT.jar
    java -cp "${CLASSPATH}:${MAIN}" com.beurive.Main

or

    SET MAIN=build\libs\app-pgp-certification-1.0-SNAPSHOT.jar
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

# What are certificates ?

Se [PGP Certificate](https://www.w3.org/PICS/DSig/pgpcert_1_0.html)

Certificates are digital documents attesting to the binding of a public key to an individual or other entity. They allow verification of the claim that a given public key does in fact belong to a given individual. Certificates help prevent someone from using a phony key to impersonate someone else.

In their simplest form, certificates contain a public key and a name. As commonly used, a certificate also contains an expiration date, the name of the certifying authority that issued the certificate, a serial number, and perhaps other information. Most importantly, it contains the digital signature of the certificate issuer. The most widely accepted format for certificates is defined by the ITU-T X.509 international standard (see Question 165); thus, certificates can be read or written by any application complying with X.509.




 