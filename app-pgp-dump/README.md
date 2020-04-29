# Description

Illustrates the dump of a PGP document.

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)
* [Bouncy Castle OpenPGP API » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk15to18/1.65)

# Documentation

* [RFC 4880](https://tools.ietf.org/html/rfc4880)

# Technical notes

## Run the example

    java -cp "build/libs/app-pgp-dump-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/bcpg-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/utils-1.0-SNAPSHOT.jar" com.beurive.Main

or

    java -cp "build\libs\app-pgp-dump-1.0-SNAPSHOT.jar;%PROJECT_ROOT_DIR%\lib\bcprov-jdk15to18-1.65.jar;%PROJECT_ROOT_DIR%\lib\bcpg-jdk15to18-1.65.jar;%PROJECT_ROOT_DIR%\lib\utils-1.0-SNAPSHOT.jar" com.beurive.Main

> Make sure to run `gradle setup` (at the project root level) first.

The program uses 1 file: `data/secret-keyring.pgp`. This file contains a sample secret key ring (passphrase is `password`).
This key ring contains 3 keys:

    List of key IDs in the secret key ring "./data/secret-keyring.pgp":
            - F52712127A58D490 (sign ? yes, master ? yes)
            - DF4C6FED0763B6A9 (sign ? yes, master ? no)
            - 1CAC39B3C005457C (sign ? no, master ? no)

The program generates 1 file: `data/signature-master.pgp`

## GPG verifications

We will check that the generated signatures can be verified using GPG.

The ID of the key master key is `F52712127A58D490`.

Import this key into the GPG private and public key rings.
    
    $ gpg --import data/secret-keyring.pgp # (password: "password")
    $ gpg --import data/public-keyring.pgp

Once this is done, we must declare the master key into the GPG [trust database](https://unix.stackexchange.com/questions/407062/gpg-list-keys-command-outputs-uid-unknown-after-importing-private-key-onto). 

    & gpg --edit-key F52712127A58D490
    -> "trust" [ENTER]
    -> "5" [ENTER]
    -> "o" [ENTER]
    -> "quit" [ENTER]
    
For GPG only, you need to [cross-certify](https://gnupg.org/faq/subkey-cross-certify.html) the keys:

    $ gpg --edit-key F52712127A58D490
    -> "cross-certify" [ENTER]
    -> "quit"
    -> "y" [ENTER]

OK. Now you can verify the signatures.
    
    $ gpg --verify data/signature-master.pgp
    gpg: Note: sender requested "for-your-eyes-only"
    gpg: Signature made Wed 29 Apr 2020 04:58:30 PM CEST
    gpg:                using RSA key F52712127A58D490
    gpg:                issuer "owner@email.com"
    gpg: Good signature from "owner@email.com" [ultimate]

This signature is valid. **Therefore, the structure of the PGP document should be valid**.

Let's look at this signature document:

    $ gpg --list-packet --verbose data/signature-master.pgp
    gpg: armor header: Version: BCPG v1.65
    # off=0 ctb=a3 tag=8 hlen=1 plen=0 indeterminate
    :compressed packet: algo=2
    # off=2 ctb=90 tag=4 hlen=2 plen=13
    :onepass_sig packet: keyid F52712127A58D490
            version 3, sigclass 0x00, digest 8, pubkey 1, last=1
    # off=17 ctb=cb tag=11 hlen=2 plen=39 new-ctb
    :literal data packet:
            mode b (62), created 1588172310, name="_CONSOLE",
            raw data: 25 bytes
    # off=58 ctb=88 tag=2 hlen=2 plen=173
    :signature packet: algo 1, keyid F52712127A58D490
            version 4, created 1588172310, md5len 0, sigclass 0x00
            digest algo 8, begin of digest e4 29
            hashed subpkt 2 len 4 (sig created 2020-04-29)
            hashed subpkt 28 len 15 (signer's user ID)
            subpkt 16 len 8 (issuer key ID F52712127A58D490)
            data: 497E7E897D68C8597259100C69A16033B22EB741F6E8AC2466B3DDE7E889630D12B770732071E65E7611C8D90F5A9D2307DDEFCC0182B73F76E9CF388B4066484C64EC9FE234EDD95B0ED8B2E734DDCC9207925F70F5EE9FA678BAB6FEC52C64748E18B52822EADCA24D03C9115BD9BD501008AC06858B11599CFBF9B6BF18B5

We have 3 packets:

* A [One-Pass Signature Packet](https://tools.ietf.org/html/rfc4880#section-4.3) - tag = 4
* A [Literal Data Packet](https://tools.ietf.org/html/rfc4880#section-4.3) - tag = 11
* A [Signature Packet](https://tools.ietf.org/html/rfc4880#section-4.3) - tag = 2

However, when we run the program, we get:

    $ java -cp "build/libs/app-pgp-dump-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/bcpg-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/utils-1.0-SNAPSHOT.jar" com.beurive.Main
    List of key IDs in the secret key ring "./data/secret-keyring.pgp":
            - F52712127A58D490 (sign ? yes, master ? yes)
            - DF4C6FED0763B6A9 (sign ? yes, master ? no)
            - 1CAC39B3C005457C (sign ? no, master ? no)
    Sign <This the document to sign> using the master key => "./data/signature-master.pgp".
    Tags for the PGP document "./data/signature-master.pgp":
      - [1] tag = 4
      - [2] tag = 11
      - [3] tag = 20
    java.io.IOException: invalid header encountered
            at org.bouncycastle.bcpg.BCPGInputStream.readPacket(Unknown Source)
            at com.beurive.Main.listPacketTags(Main.java:244)
            at com.beurive.Main.main(Main.java:274)
