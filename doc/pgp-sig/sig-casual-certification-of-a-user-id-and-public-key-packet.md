# 0x12: Casual certification of a User ID and Public-Key packet

> The issuer of this certification has done some casual
> verification of the claim of identity.

This type of signature is generated when a user signs another user key.

Let say the user Suzy signs Henry's key.

    gpg --list-keys

* **Suzy**: `suzy@company.com`    
* **Henry**: `henry@company.com`

Suzy signs Henry's key.

    gpg --sign-key -u suzy@company.com --default-cert-level 2 henry@company.com
    
> Please note the use of the option [--default-cert-level](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html).

Export Joe's key:

    gpg --output henry.key --export henry@company.com

Let inspect Joe's key:

    gpg --list-packet henry.key
    
    # off=0 ctb=99 tag=6 hlen=3 plen=269
    :public key packet:
            version 4, algo 1, created 1591021065, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: D9FCF703D7F7501A
    # off=272 ctb=b4 tag=13 hlen=2 plen=29
    :user ID packet: "Henry GPG <henry@company.com>"
    # off=303 ctb=89 tag=2 hlen=3 plen=334
    :signature packet: algo 1, keyid D9FCF703D7F7501A
            version 4, created 1591021065, md5len 0, sigclass 0x13
            digest algo 8, begin of digest 49 6e
            hashed subpkt 33 len 21 (issuer fpr v4 DF5B2DC2FD3DF8D592BBE64ED9FCF703D7F7501A)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 03)
            hashed subpkt 11 len 4 (pref-sym-algos: 9 8 7 2)
            hashed subpkt 21 len 5 (pref-hash-algos: 10 9 8 11 2)
            hashed subpkt 22 len 3 (pref-zip-algos: 2 3 1)
            hashed subpkt 30 len 1 (features: 01)
            hashed subpkt 23 len 1 (keyserver preferences: 80)
            subpkt 16 len 8 (issuer key ID D9FCF703D7F7501A)
            data: [2047 bits]
    # off=640 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591021132, md5len 0, sigclass 0x12
            digest algo 8, begin of digest 8d 1a
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2045 bits]
    # off=950 ctb=b9 tag=14 hlen=3 plen=269
    :public sub key packet:
            version 4, algo 1, created 1591021065, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: 2BE2A0951AD37749
    # off=1222 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid D9FCF703D7F7501A
            version 4, created 1591021065, md5len 0, sigclass 0x18
            digest algo 8, begin of digest cf b7
            hashed subpkt 33 len 21 (issuer fpr v4 DF5B2DC2FD3DF8D592BBE64ED9FCF703D7F7501A)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 0C)
            subpkt 16 len 8 (issuer key ID D9FCF703D7F7501A)
            data: [2044 bits]
    
We notice the _Casual certification of a User ID and Public-Key packet_ (`sigclass 0x12`):

    # off=640 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591021132, md5len 0, sigclass 0x12
            digest algo 8, begin of digest 8d 1a
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2045 bits]
