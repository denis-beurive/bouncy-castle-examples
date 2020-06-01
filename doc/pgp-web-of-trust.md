# Web of trust

Let's create 2 keyrings:
* one keyring for Bob.
* ont keyring for Alice.

And let's assume that:

* Bob vouch that Alice's key belongs to Alice by adding my signature to it.
* Alice vouch that Alice's key belongs to Bob by adding my signature to it.

Create the keys for Alice and Bob:

    gpg --full-generate-key

Bob:

    pub   rsa2048 2020-05-24 [SC]
          BF639C0FD3CD3872828856C3B1589F0D0EA747F5
    uid                      Bod the GPG user <bob@company.com>
    sub   rsa2048 2020-05-24 [E]

Alice:

    pub   rsa2048 2020-05-24 [SC]
          988D01E79CB610872D0C6D2051227F61976B0759
    uid                      Alice the GPG user <alice@company.com>
    sub   rsa2048 2020-05-24 [E]

Exportation:

    gpg --armor --output pub-bob.key --export BF639C0FD3CD3872828856C3B1589F0D0EA747F5
    gpg --armor --output sec-bob.key --export-secret-keys BF639C0FD3CD3872828856C3B1589F0D0EA747F5
    gpg --armor --output pub-alice.key --export 988D01E79CB610872D0C6D2051227F61976B0759
    gpg --armor --output sec-alice.key --export-secret-keys 988D01E79CB610872D0C6D2051227F61976B0759
    
Bob signs Alice's public key:

    gpg --sign-key -u bob@company.com --ask-cert-level alice@company.com
    
Alice signs Bob's public key:
    
    gpg --sign-key -u alice@company.com --ask-cert-level bob@company.com

Export the keys again:
    
    gpg --armor --output signed-pub-bob.key --export BF639C0FD3CD3872828856C3B1589F0D0EA747F5
    gpg --armor --output signed-sec-bob.key --export-secret-keys BF639C0FD3CD3872828856C3B1589F0D0EA747F5
    gpg --armor --output signed-pub-alice.key --export 988D01E79CB610872D0C6D2051227F61976B0759
    gpg --armor --output signed-sec-alice.key --export-secret-keys 988D01E79CB610872D0C6D2051227F61976B0759

Export the keys structures before and after the signature process:

    # Bob's key (signed by Alice)
    gpg --list-packet pub-bob.key > pub-bob.key.txt
    gpg --list-packet signed-pub-bob.key > signed-pub-bob.key.txt
    
    # Alice's key (signed by Bob)
    gpg --list-packet pub-alice.key > pub-alice.key.txt
    gpg --list-packet signed-pub-alice.key > signed-pub-alice.key.txt
    
Then compare the keys structures before and after the signature process:

[pub-alice.key.txt](pgp-web-of-trust/pub-alice.key.txt) and [signed-pub-alice.key.txt](pgp-web-of-trust/signed-pub-alice.key.txt).

![](pgp-web-of-trust/bob-signed-alice.PNG)

[pub-bob.key.txt](pgp-web-of-trust/pub-bob.key.txt) and [signed-pub-bob.key.txt](pgp-web-of-trust/signed-pub-bob.key.txt).

![](pgp-web-of-trust/alice-signed-bob.PNG)

A [Positive certification of a User ID and Public-Key packet (0x13)](https://tools.ietf.org/html/rfc4880#section-5.2.1) has been added.

Bob's key, signed by Alice:

    # off=645 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid 51227F61976B0759
        version 4, created 1590353367, md5len 0, sigclass 0x13
        digest algo 8, begin of digest 70 cd
        hashed subpkt 33 len 21 (issuer fpr v4 988D01E79CB610872D0C6D2051227F61976B0759)
        hashed subpkt 2 len 4 (sig created 2020-05-24)
        subpkt 16 len 8 (issuer key ID 51227F61976B0759)
        data: [2047 bits]

Issuer key ID `51227F61976B0759`. This is Alice's key.

Alice's key, signed by Bob:

    # off=649 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid B1589F0D0EA747F5
        version 4, created 1590353270, md5len 0, sigclass 0x13
        digest algo 8, begin of digest 82 cc
        hashed subpkt 33 len 21 (issuer fpr v4 BF639C0FD3CD3872828856C3B1589F0D0EA747F5)
        hashed subpkt 2 len 4 (sig created 2020-05-24)
        subpkt 16 len 8 (issuer key ID B1589F0D0EA747F5)
        data: [2044 bits]
	
Issuer key ID `B1589F0D0EA747F5`. This is Bob's key.

> Please note that there are [4 types of key certification](https://tools.ietf.org/html/rfc4880#section-5.2.1).
> * **0x10**: Generic certification of a User ID and Public-Key packet
> * **0x11**: Persona certification of a User ID and Public-Key packet.
> * **0x12**: Casual certification of a User ID and Public-Key packet.
> * **0x13**: Positive certification of a User ID and Public-Key packet.

Please also note that only primary/master keys can be used to generate certification signatures.
See [Key Structures](https://tools.ietf.org/html/rfc4880#section-12.1): 

> In a V4 key, the primary key MUST be a key capable of certification.
> The subkeys may be keys of any other type.  There may be other
> constructions of V4 keys, too.

