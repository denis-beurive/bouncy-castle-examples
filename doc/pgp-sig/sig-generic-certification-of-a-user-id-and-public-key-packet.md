# 0x10: Generic certification of a User ID and Public-Key packet

> The issuer of this certification does not make any particular
> assertion as to how well the certifier has checked that the owner
> of the key is in fact the person described by the User ID.

This type of signature is generated when a user signs another user key.

Let say the user Joe signs Suzy's key.

    gpg --list-keys

* **Suzy**: `suzy@company.com`    
* **Joe**: `joe@company.com`

Joe signs Suzy's key.

    gpg --sign-key -u joe@company.com --default-cert-level 0 suzy@company.com
    
> Please note the use of the option [--default-cert-level](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html).

Export Suzy's key:

    gpg --output suzy.key --export suzy@company.com

Let inspect Suzy's key:

    gpg --list-packet suzy.key
    
    # off=0 ctb=99 tag=6 hlen=3 plen=269
    :public key packet:
            version 4, algo 1, created 1591019046, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: C7DF3E893E94E196
    # off=272 ctb=b4 tag=13 hlen=2 plen=27
    :user ID packet: "Suzy GPG <suzy@company.com>"
    # off=301 ctb=89 tag=2 hlen=3 plen=334
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591019046, md5len 0, sigclass 0x13
            digest algo 8, begin of digest d1 71
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 03)
            hashed subpkt 11 len 4 (pref-sym-algos: 9 8 7 2)
            hashed subpkt 21 len 5 (pref-hash-algos: 10 9 8 11 2)
            hashed subpkt 22 len 3 (pref-zip-algos: 2 3 1)
            hashed subpkt 30 len 1 (features: 01)
            hashed subpkt 23 len 1 (keyserver preferences: 80)
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2045 bits]
    # off=638 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid 774FE9EEEC882920
            version 4, created 1591019609, md5len 0, sigclass 0x10
            digest algo 8, begin of digest 3c 58
            hashed subpkt 33 len 21 (issuer fpr v4 E0B43A3DBB54AE534088E36E774FE9EEEC882920)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            subpkt 16 len 8 (issuer key ID 774FE9EEEC882920)
            data: [2046 bits]
    # off=948 ctb=b9 tag=14 hlen=3 plen=269
    :public sub key packet:
            version 4, algo 1, created 1591019046, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: C7072BF6E5D16141
    # off=1220 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591019046, md5len 0, sigclass 0x18
            digest algo 8, begin of digest f4 08
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 0C)
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2046 bits]

We notice the _Generic certification of a User ID and Public-Key packet_ (`sigclass 0x10`):

    # off=638 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid 774FE9EEEC882920
            version 4, created 1591019609, md5len 0, sigclass 0x10
            digest algo 8, begin of digest 3c 58
            hashed subpkt 33 len 21 (issuer fpr v4 E0B43A3DBB54AE534088E36E774FE9EEEC882920)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            subpkt 16 len 8 (issuer key ID 774FE9EEEC882920)
            data: [2046 bits]
