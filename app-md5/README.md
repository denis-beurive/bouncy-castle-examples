# Description

Illustrates the use of the [MD5](https://en.wikipedia.org/wiki/MD5) algorithm.

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)

# Documentation

* [MD5Digest](https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/crypto/digests/MD5Digest.html)

# Technical notes

## Run the example

    java -cp "build/libs/app-md5-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar" com.beurive.Main

> Make sure to run `gradle getDeps` (at the project root level) first.

## Notes

* Digest size: 16 bytes 




