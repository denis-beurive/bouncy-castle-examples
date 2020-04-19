# Description

Illustrates the use of the streams.

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)

# Documentation

* [TigerDigest](https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/crypto/digests/TigerDigest.html)

# Technical notes

## Run the example

    java -cp "build/libs/app-streams-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar" com.beurive.Main

or

    java -cp "build\libs\app-streams-1.0-SNAPSHOT.jar;%PROJECT_ROOT_DIR%\lib\bcprov-jdk15to18-1.65.jar" com.beurive.Main

> Make sure to run `gradle setup` (at the project root level) first.

## Notes

* Digest size: 24 bytes




