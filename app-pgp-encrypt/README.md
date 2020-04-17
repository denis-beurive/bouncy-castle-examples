# Description

Illustrates the PGP encryption process. This program uses:

* An input file that will be encrypted.
* A (public) keyring.

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)
* [Bouncy Castle OpenPGP API » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk15to18/1.65)

# Technical notes

## Run the example

    java -cp "build/libs/app-pgp-encrypt-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/bcpg-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/utils-1.0-SNAPSHOT.jar" com.beurive.Main

or

    java -cp "build\libs\app-pgp-encrypt-1.0-SNAPSHOT.jar;%PROJECT_ROOT_DIR%\lib\bcprov-jdk15to18-1.65.jar;%PROJECT_ROOT_DIR%\lib\bcpg-jdk15to18-1.65.jar;%PROJECT_ROOT_DIR%\lib\utils-1.0-SNAPSHOT.jar" com.beurive.Main

> Make sure to run `gradle setup` (at the project root level) first.

Examine the encrypted document:

    gpg --list-packets --verbose data/encrypted-file.pgp
