# 0x11: Persona certification of a User ID and Public-Key packet

> The issuer of this certification has not done any verification of
> the claim that the owner of this key is the User ID specified.

See [RFC 4880: Notes on Self-Signatures](https://tools.ietf.org/html/rfc4880#section-5.2.3.3)

This type of signature is generated when a user signs another user key.

Let say the user Suzy signs Joe's key.

    gpg --list-keys

* **Suzy**: `suzy@company.com`    
* **Joe**: `joe@company.com`

Suzy signs Joe's key.

    gpg --sign-key -u suzy@company.com --default-cert-level 1 joe@company.com
    
> Please note the use of the option [--default-cert-level](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html).

Export Joe's key:

    gpg --output joe.key --export joe@company.com

Let inspect Joe's key:

    gpg --list-packet joe.key
    
    # off=0 ctb=99 tag=6 hlen=3 plen=269
    :public key packet:
            version 4, algo 1, created 1591019108, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: 774FE9EEEC882920
    # off=272 ctb=b4 tag=13 hlen=2 plen=25
    :user ID packet: "Joe GPG <joe@company.com>"
    # off=299 ctb=89 tag=2 hlen=3 plen=334
    :signature packet: algo 1, keyid 774FE9EEEC882920
            version 4, created 1591019108, md5len 0, sigclass 0x13
            digest algo 8, begin of digest a0 84
            hashed subpkt 33 len 21 (issuer fpr v4 E0B43A3DBB54AE534088E36E774FE9EEEC882920)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 03)
            hashed subpkt 11 len 4 (pref-sym-algos: 9 8 7 2)
            hashed subpkt 21 len 5 (pref-hash-algos: 10 9 8 11 2)
            hashed subpkt 22 len 3 (pref-zip-algos: 2 3 1)
            hashed subpkt 30 len 1 (features: 01)
            hashed subpkt 23 len 1 (keyserver preferences: 80)
            subpkt 16 len 8 (issuer key ID 774FE9EEEC882920)
            data: [2048 bits]
    # off=636 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591020543, md5len 0, sigclass 0x11
            digest algo 8, begin of digest 7c 5f
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2048 bits]
    # off=946 ctb=b9 tag=14 hlen=3 plen=269
    :public sub key packet:
            version 4, algo 1, created 1591019108, expires 0
            pkey[0]: [2048 bits]
            pkey[1]: [17 bits]
            keyid: 328760125FC20E9D
    # off=1218 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid 774FE9EEEC882920
            version 4, created 1591019108, md5len 0, sigclass 0x18
            digest algo 8, begin of digest 67 3b
            hashed subpkt 33 len 21 (issuer fpr v4 E0B43A3DBB54AE534088E36E774FE9EEEC882920)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 0C)
            subpkt 16 len 8 (issuer key ID 774FE9EEEC882920)
            data: [2048 bits]

We notice the _Persona certification of a User ID and Public-Key packet_ (`sigclass 0x11`):

    # off=636 ctb=89 tag=2 hlen=3 plen=307
    :signature packet: algo 1, keyid C7DF3E893E94E196
            version 4, created 1591020543, md5len 0, sigclass 0x11
            digest algo 8, begin of digest 7c 5f
            hashed subpkt 33 len 21 (issuer fpr v4 9F557A19F618ED05F8FF9D6CC7DF3E893E94E196)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            subpkt 16 len 8 (issuer key ID C7DF3E893E94E196)
            data: [2048 bits]
