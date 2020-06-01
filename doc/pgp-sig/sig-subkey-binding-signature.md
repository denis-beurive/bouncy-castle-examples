# 0x18: Subkey Binding Signature

> This signature is a statement by the top-level signing key that
> indicates that it owns the subkey.  This signature is calculated
> directly on the primary key and subkey, and not on any User ID or
> other packets.  A signature that binds a **signing subkey** MUST have
> an **Embedded Signature _subpacket_ in this binding signature that
> contains a 0x19 signature** made by the signing subkey on the
> primary key and subkey.

This signature is added to all subkeys.

Let's dump a key (or keyring):

    gpg --output bertrand.key --export bertrand@company.com
    
Then let inspect the key (or keyring):

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
      
We notice the presence of the Subkey Binding Signature (`sigclass 0x18`):
      
    # off=914 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid 3559C947CA49C02B
            version 4, created 1591022801, md5len 0, sigclass 0x18
            digest algo 8, begin of digest 48 7b
            hashed subpkt 33 len 21 (issuer fpr v4 F890D87039FFAFB622B4C9B03559C947CA49C02B)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 27 len 1 (key flags: 0C)
            subpkt 16 len 8 (issuer key ID 3559C947CA49C02B)
            data: [2042 bits]

> This means that the subkey identified by the ID `D04E1857C36C89A1` is bound to the _master
> key_ identified by the ID `3559C947CA49C02B`.

Please note that, as you can see, the subkey identified by the ID `D04E1857C36C89A1` is not a signing subkey:

    gpg --list-keys D04E1857C36C89A1
    
    gpg: vérification de la base de confiance
    gpg: marginals needed: 3  completes needed: 1  trust model: pgp
    gpg: profondeur : 0  valables :  30  signées :   0
         confiance : 0 i., 0 n.d., 0 j., 0 m., 0 t., 30 u.
    pub   rsa2048 2020-06-01 [SC]
          F890D87039FFAFB622B4C9B03559C947CA49C02B
    uid          [  ultime ] Bertrand <bertrand@company.com>
    sub   rsa2048 2020-06-01 [E]

> Pay attention to the last line `sub   rsa2048 2020-06-01 [E]`.
> This line means that the subkey is an encryption key (`[E]`, like _encryption_).
> That's why the associated Subkey Binding Signature does not contain any
> subpacket of type `0x19`.
