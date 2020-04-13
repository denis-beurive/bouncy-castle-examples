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

Then, download the required dependencies:

    gradle getDeps
    
Finally, build all the example applications:

    gradle build
    
# Examples

## Block ciphers

| Algorithm | Cypher mode | Example                                 |
|-----------|-------------|-----------------------------------------|
| DES       | CBC         | [app-cbc-des/](app-cbc-des/README.md)   |
| DES       | CFB         | [app-cfb-des/](app-cfb-des/README.md)   |
| DES       | OFB         | [app-ofb-des/](app-ofb-des/README.md)   |
| AES       | CBC         | [app-cbc-aes/](app-cbc-aes/README.md)   |
| 3DES      | CBC         | [app-cbc-3des/](app-cbc-3des/README.md) |

## Hash algorithms

| Algorithm | Example                                 |
|-----------|-----------------------------------------|
| SHA256    | [app-sha256/](app-sha256/README.md)     |
| SHA512    | [app-sha512/](app-sha512/README.md)     |
| MD5       | [app-md5/](app-md5/README.md)           |
| Tiger     | [app-tiger/](app-tiger/README.md)       |

## PGP

Please note the terms "key" and "subkey" may be confusing.

> [What exactly is a subkey?](https://security.stackexchange.com/questions/76940/what-exactly-is-a-subkey)
>
> Originally in PGP 2.6, back in the early 90s, you had just one keypair and it was used for both encryption and signing. The ability to have additional keypairs presented some engineering challenges. Ultimately, it was decided that the additonal keypairs would be called "subkeys", despite the fact there's nothing "sub" about them. Likewise, what you call your "key" isn't really a key at all--the terminology is a holdover from the days when a key really was a key. Nowadays, a key is really a collection of keys, along with some metadata for user identifiers, signatures, etc.
>
> E.g., my "key" has four keypairs on it: 5B8709EB, D0C6AAE4, 71E177DB and 8DB02BBB3.
>
> What GnuPG calls your "public key" is really the oldest signing key in the collection. E.g., since 5B8709EB was created first, GnuPG calls the entire set of keys and metadata the "5B8709EB key".
>
> So, "is it possible to have a key that's used for encryption and signing without any subkey at all?" The answer here is no, because all keypairs on a key are subkeys. Even if there's only one of them. 

| Action               | Example                                       | Notes                                  |
|----------------------|-----------------------------------------------|-----------------------------------------
| Key generation       | [app-pgp-keygen/](app-pgp-keygen/README.md)   | see note about key/keyring             |
| PGP Document loading | [app-pgp-keyload/](app-pgp-keyload/README.md) | key, keyring, encrypted document...    |
