# 0x19: Primary Key Binding Signature

> This signature is a statement by a **signing subkey**, indicating
> that it is owned by the primary key and subkey.  This signature
> is calculated the same way as a 0x18 signature: directly on the
> primary key and subkey, and not on any User ID or other packets.

This signature is embedded in a [Subkey Binding Signature (0x18)](https://tools.ietf.org/html/rfc4880#section-5.2.1),
within an [Embedded Signature](https://tools.ietf.org/html/rfc4880#section-5.2.3.1) subpacket.

Add a signing subkey to an existing keyring:

    gpg --edit-key bertrand@company.com
    addkey [ENTER]
    4 [ENTER]
    2048 [ENTER]
    0 [ENTER]
    o [ENTER] 
    o [ENTER]
    save [ENTER]
    
Make sure the created subkey is indeed a signing subkey:

    gpg --list-keys bertrand@company.com
    
    pub   rsa2048 2020-06-01 [SC]
          F890D87039FFAFB622B4C9B03559C947CA49C02B
    uid          [  ultime ] Bertrand <bertrand@company.com>
    sub   rsa2048 2020-06-01 [E]
    sub   rsa2048 2020-06-01 [S]

> Pay attention to the last line `sub   rsa2048 2020-06-01 [S]`.
> This line means that the subkey is a signing key (`[S]`, like _signing_).

Now, let's inspect the key:

    gpg --output bertrand.key --export bertrand@company.com

    gpg --list-packet bertrand.key
    
    # off=0 ctb=99 tag=6 hlen=3 plen=269
    :public key packet:
            version 4, algo 1, created 1591022801, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: 3559C947CA49C02B
    # off=272 ctb=b4 tag=13 hlen=2 plen=31
    :user ID packet: "Bertrand <bertrand@company.com>"
    # off=305 ctb=89 tag=2 hlen=3 plen=334
    :signature packet: algo 1, keyid 3559C947CA49C02B
            version 4, created 1591022801, md5len 0, sigclass 0x13
            digest algo 8, begin of digest 05 43
            hashed subpkt 33 len 21 (issuer fpr v4 F890D87039FFAFB622B4C9B03559C947CA49C02B)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 03)
            hashed subpkt 11 len 4 (pref-sym-algos: 9 8 7 2)
            hashed subpkt 21 len 5 (pref-hash-algos: 10 9 8 11 2)
            hashed subpkt 22 len 3 (pref-zip-algos: 2 3 1)
            hashed subpkt 30 len 1 (features: 01)
            hashed subpkt 23 len 1 (keyserver preferences: 80)
            subpkt 16 len 8 (issuer key ID 3559C947CA49C02B)
            data: [2047 bits]
    # off=642 ctb=b9 tag=14 hlen=3 plen=269
    :public sub key packet:
            version 4, algo 1, created 1591022801, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: D04E1857C36C89A1
    # off=914 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid 3559C947CA49C02B
            version 4, created 1591022801, md5len 0, sigclass 0x18
            digest algo 8, begin of digest 48 7b
            hashed subpkt 33 len 21 (issuer fpr v4 F890D87039FFAFB622B4C9B03559C947CA49C02B)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 0C)
            subpkt 16 len 8 (issuer key ID 3559C947CA49C02B)
            data: [2042 bits]
    # off=1227 ctb=b9 tag=14 hlen=3 plen=269
    :public sub key packet:
            version 4, algo 1, created 1591024286, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: 86F4FBD96E2B24AD
    # off=1499 ctb=89 tag=2 hlen=3 plen=620
    :signature packet: algo 1, keyid 3559C947CA49C02B
            version 4, created 1591024286, md5len 0, sigclass 0x18
            digest algo 8, begin of digest 5f d7
            hashed subpkt 33 len 21 (issuer fpr v4 F890D87039FFAFB622B4C9B03559C947CA49C02B)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 02)
            subpkt 16 len 8 (issuer key ID 3559C947CA49C02B)
            subpkt 32 len 307 (signature: v4, class 0x19, algo 1, digest algo 8)
            data: [2047 bits]

Please pay attention to the following line:

    subpkt 32 len 307 (signature: v4, class 0x19, algo 1, digest algo 8)
    
* [subpkt 32](https://tools.ietf.org/html/rfc4880#section-5.2.3.1) means that the subpacket contains an embedded signature.
* [class 0x19](https://tools.ietf.org/html/rfc4880#section-5.2.1) means that this signature is a Primary Key Binding Signature. 
