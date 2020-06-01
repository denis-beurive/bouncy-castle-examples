# 0x13: Positive certification of a User ID and Public-Key packet

> The issuer of this certification has done substantial
> verification of the claim of identity.
>
> Most OpenPGP implementations make their "key signatures" as 0x10
> certifications.  Some implementations can issue 0x11-0x13
> certifications, but few differentiate between the types.

This type of signature is generated when a user signs another user key.

Let say the user Suzy signs Bill's key.

    gpg --list-keys

* **Suzy**: `suzy@company.com`    
* **Bill**: `bill@company.com`

Suzy signs Bill's key.

    gpg --sign-key -u suzy@company.com --default-cert-level 3 bill@company.com
    
> Please note the use of the option [--default-cert-level](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html).

Export Bill's key:

    gpg --output bill.key --export bill@company.com

Let inspect Bill's key:

    gpg --list-packet Bill.key
    
    # off=0 ctb=99 tag=6 hlen=3 plen=269
    :public key packet:
            version 4, algo 1, created 1591021582, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: D7545427A7944291
    # off=272 ctb=b4 tag=13 hlen=2 plen=27
    :user ID packet: "Bill GPG <bill@company.com>"
    # off=301 ctb=89 tag=2 hlen=3 plen=334
    :signature packet: algo 1, keyid D7545427A7944291
            version 4, created 1591021582, md5len 0, sigclass 0x13
            digest algo 8, begin of digest 0d f7
            hashed subpkt 33 len 21 (issuer fpr v4 6E539D01D18F64AE3CF4EBB4D7545427A7944291)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 03)
            hashed subpkt 11 len 4 (pref-sym-algos: 9 8 7 2)
            hashed subpkt 21 len 5 (pref-hash-algos: 10 9 8 11 2)
            hashed subpkt 22 len 3 (pref-zip-algos: 2 3 1)
            hashed subpkt 30 len 1 (features: 01)
            hashed subpkt 23 len 1 (keyserver preferences: 80)
            subpkt 16 len 8 (issuer key ID D7545427A7944291)
            data: [2046 bits]
    # off=638 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591021696, md5len 0, sigclass 0x13
            digest algo 8, begin of digest 02 9d
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2047 bits]
    # off=948 ctb=b9 tag=14 hlen=3 plen=269
    :public sub key packet:
            version 4, algo 1, created 1591021582, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: 3178DB07948581AC
    # off=1220 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid D7545427A7944291
            version 4, created 1591021582, md5len 0, sigclass 0x18
            digest algo 8, begin of digest b6 5d
            hashed subpkt 33 len 21 (issuer fpr v4 6E539D01D18F64AE3CF4EBB4D7545427A7944291)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 0C)
            subpkt 16 len 8 (issuer key ID D7545427A7944291)
            data: [2048 bits]
            
We notice the _Positive certification of a User ID and Public-Key packet_ (`sigclass 0x13`):

    # off=638 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591021696, md5len 0, sigclass 0x13
            digest algo 8, begin of digest 02 9d
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2047 bits]
