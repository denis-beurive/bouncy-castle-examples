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

| Algorithm | Cypher mode | Example                                 |
|-----------|-------------|-----------------------------------------|
| DES       | CBC         | [app-cbc-des/](app-cbc-des/README.md)   |
| DES       | CFB         | [app-cfb-des/](app-cfb-des/README.md)   |
| DES       | OFB         | [app-ofb-des/](app-ofb-des/README.md)   |
| AES       | CBC         | [app-cbc-aes/](app-cbc-aes/README.md)   |
| 3DES      | CBC         | [app-cbc-3des/](app-cbc-3des/README.md) |