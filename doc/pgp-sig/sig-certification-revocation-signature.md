# 0x30: Certification revocation signature

> This signature revokes an earlier User ID certification signature
> (signature class 0x10 through 0x13) or direct-key signature
> (0x1F).  It should be issued by the same key that issued the
> revoked signature or an authorized revocation key.  The signature
> is computed over the same data as the certificate that it
> revokes, and should have a later creation date than that
> certificate.

To illustrate this type of signature, let’s revoke a previously
generated certification signature.

Let's consider this key/keyring:

    gpg --list-packet billy.key
    
    # off=0 ctb=99 tag=6 hlen=3 plen=269
    :public key packet:
            version 4, algo 1, created 1591041052, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: 2DC01948B090FE62
    # off=272 ctb=b4 tag=13 hlen=2 plen=25
    :user ID packet: "Billy <billy@company.com>"
    # off=299 ctb=89 tag=2 hlen=3 plen=334
    :signature packet: algo 1, keyid 2DC01948B090FE62
            version 4, created 1591041052, md5len 0, sigclass 0x13
            digest algo 8, begin of digest eb 0f
            hashed subpkt 33 len 21 (issuer fpr v4 93EA47DCD6CF11F8AB71969E2DC01948B090FE62)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 03)
            hashed subpkt 11 len 4 (pref-sym-algos: 9 8 7 2)
            hashed subpkt 21 len 5 (pref-hash-algos: 10 9 8 11 2)
            hashed subpkt 22 len 3 (pref-zip-algos: 2 3 1)
            hashed subpkt 30 len 1 (features: 01)
            hashed subpkt 23 len 1 (keyserver preferences: 80)
            subpkt 16 len 8 (issuer key ID 2DC01948B090FE62)
            data: [2048 bits]
    # off=636 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591041219, md5len 0, sigclass 0x13
            digest algo 8, begin of digest 51 26
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2047 bits]
    # off=946 ctb=b9 tag=14 hlen=3 plen=269
    :public sub key packet:
            version 4, algo 1, created 1591041052, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: 855766ACAD69CFEC
    # off=1218 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid 2DC01948B090FE62
            version 4, created 1591041052, md5len 0, sigclass 0x18
            digest algo 8, begin of digest a2 f3
            hashed subpkt 33 len 21 (issuer fpr v4 93EA47DCD6CF11F8AB71969E2DC01948B090FE62)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 0C)
            subpkt 16 len 8 (issuer key ID 2DC01948B090FE62)
            data: [2047 bits]

We can see that this key has been certified:

    # off=636 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591041219, md5len 0, sigclass 0x13
            digest algo 8, begin of digest 51 26
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2047 bits]

And the identity of the certifier is `suzy@company.com`:
`subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)` and:
    
    gpg --list-key C7DF3E893E94E196
    
    pub   rsa2048 2020-06-01 [SC]
          9F557A19F618ED05F8FF9D6CC7DF3E893E94E196
    uid          [  ultime ] Suzy GPG <suzy@company.com>
    sub   rsa2048 2020-06-01 [E]

That is: `suzy@company.com` issued a [Positive certification of a User ID and Public-Key packet (sigclass 0x13)](https://tools.ietf.org/html/rfc4880#section-5.2.1)
on `billy@company.com` key.

Lets's revoke this Casual certification of a User ID and Public-Key packet.

    gpg --edit-key billy@company.com
        
Type `revsig` [ENTER]

    gpg> revsig
    You have signed these user IDs on key 2DC01948B090FE62:
         Billy <billy@company.com>
       signed by your key 2DC01948B090FE62 on 2020-06-01
       signed by your key C7DF3E893E94E196 on 2020-06-01
    
    user ID: "Billy <billy@company.com>"
    signed by your key 2DC01948B090FE62 on 2020-06-01
    Create a revocation certificate for this signature? (y/N)

Type `N` [ENTER]

    user ID: "Billy <billy@company.com>"
    signed by your key C7DF3E893E94E196 on 2020-06-01
    Create a revocation certificate for this signature? (y/N)

Type `y` [ENTER]

    You are about to revoke these signatures:
         Billy <billy@company.com>
       signed by your key C7DF3E893E94E196 on 2020-06-01
    Really create the revocation certificates? (y/N)

Type `y` [ENTER]

Then `0` [ENTER] => [ENTER] => `y` [ENTER] => `save` [ENTER]

Now, let's examine the structure of the key.

Dump the key in a file:

    gpg --output billy-revoked.key --export billy@company.com 

Dump the structure of the key: 

    gpg --list-packet billy-revoked.key

    # off=0 ctb=99 tag=6 hlen=3 plen=269
    :public key packet:
            version 4, algo 1, created 1591041052, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: 2DC01948B090FE62
    # off=272 ctb=b4 tag=13 hlen=2 plen=25
    :user ID packet: "Billy <billy@company.com>"
    # off=299 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591042594, md5len 0, sigclass 0x30
            digest algo 8, begin of digest de be
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 29 len 1 (revocation reason 0x00 ())
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2048 bits]
    # off=612 ctb=89 tag=2 hlen=3 plen=334
    :signature packet: algo 1, keyid 2DC01948B090FE62
            version 4, created 1591041052, md5len 0, sigclass 0x13
            digest algo 8, begin of digest eb 0f
            hashed subpkt 33 len 21 (issuer fpr v4 93EA47DCD6CF11F8AB71969E2DC01948B090FE62)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 03)
            hashed subpkt 11 len 4 (pref-sym-algos: 9 8 7 2)
            hashed subpkt 21 len 5 (pref-hash-algos: 10 9 8 11 2)
            hashed subpkt 22 len 3 (pref-zip-algos: 2 3 1)
            hashed subpkt 30 len 1 (features: 01)
            hashed subpkt 23 len 1 (keyserver preferences: 80)
            subpkt 16 len 8 (issuer key ID 2DC01948B090FE62)
            data: [2048 bits]
    # off=949 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591041219, md5len 0, sigclass 0x13
            digest algo 8, begin of digest 51 26
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2047 bits]
    # off=1259 ctb=b9 tag=14 hlen=3 plen=269
    :public sub key packet:
            version 4, algo 1, created 1591041052, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: 855766ACAD69CFEC
    # off=1531 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid 2DC01948B090FE62
            version 4, created 1591041052, md5len 0, sigclass 0x18
            digest algo 8, begin of digest a2 f3
            hashed subpkt 33 len 21 (issuer fpr v4 93EA47DCD6CF11F8AB71969E2DC01948B090FE62)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 0C)
            subpkt 16 len 8 (issuer key ID 2DC01948B090FE62)
            data: [2047 bits]
                
We can see the Certification revocation signature (`sigclass 0x30`)

    # off=299 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591042594, md5len 0, sigclass 0x30
            digest algo 8, begin of digest de be
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 29 len 1 (revocation reason 0x00 ())
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2048 bits]

The signature issuer ID is `C7DF3E893E94E196`. It identifies `suzy@company.com`.
