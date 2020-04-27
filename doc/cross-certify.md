## Cross-certification

See [Signing Subkey Cross-Certification](https://gnupg.org/faq/subkey-cross-certify.html).

It appears that the GPG way to cross-certify a sub-key is not standard.
Indeed, GPG uses a sub-packet which type is 33.
But the value (33) is not defined by [RFC 4880](https://tools.ietf.org/html/rfc4880#section-5.2.3.1).
In fact, sub-packet 33 is a GPG extension (see [this post](https://lists.gnupg.org/pipermail/gnupg-users/2018-January/059881.html)).
Therefore, do not expect to cross-certify the sub-keys using Bouncy Castle yet.

## What does GPG do to cross-certify a sub-key ?

* Generate a secret and a public key-ring (`data/public-keyring.pgp` and `data/secret-keyring.pgp`).
* Dump the content of the public key-ring into a file: `gpg --list-packets --verbose data/public-keyring.pgp > data/public-keyring-list.pgp`
* Import the key-rings into the GPG keyring: `gpg --import data/public-keyring.pgp` and `gpg --import data/secret-keyring.pgp`.
* Edit the key-rings in order to "cross-certify" the sub-keys: `gpg --edit-key <ID of the master key>` > `"cross-certify" [ENTER]` > `"o" [ENTER]`.
* Export the public key-ring: `gpg --output data/cross-certified-public-keyring.gpg --armor --export <ID of the master key>`.
* Dump the public key-ring: `gpg --list-packets --verbose data/cross-certified-public-keyring.gpg > data/cross-certified-public-keyring.lst`
* Compare `data/public-keyring.lst` (not cross-certified) and `data/cross-certified-public-keyring.lst` (cross-certified). 

**Before cross-certification**: `data/public-keyring.lst`
    
Output:

    # off=0 ctb=98 tag=6 hlen=2 plen=75
    :public key packet:
        version 4, algo 1, created 1587839289, expires 0
        pkey[0]: A60F07AEBA2CAFB169645750E1186A082B466E9B130D260252E87B003C3903B32EA03C27E4585CDDE153B139B8B3A1495C67E1113771C7E84B049A6305B6A341
        pkey[1]: 11
        keyid: E8F4828E743BD5F3
    # off=77 ctb=b4 tag=13 hlen=2 plen=15
    :user ID packet: "owner@email.com"
    # off=94 ctb=88 tag=2 hlen=2 plen=92
    :signature packet: algo 1, keyid E8F4828E743BD5F3
        version 4, created 1587839289, md5len 0, sigclass 0x13
        digest algo 8, begin of digest 49 4f
        hashed subpkt 2 len 4 (sig created 2020-04-25)
        subpkt 16 len 8 (issuer key ID E8F4828E743BD5F3)
        data: 7A0CA4D3A272AC30A9288BDFD6D9FC13858E4B4477B2F00AFB9A3E8604C0DF361BAA7A3DDF0CCDA4F6A3F95727EFA803F1CEEE45500A4CC0300E2E4493B546BC
    # off=188 ctb=b8 tag=14 hlen=2 plen=75
    :public sub key packet:
        version 4, algo 1, created 1587839289, expires 0
        pkey[0]: CB5596CEF89C6BD5C284C0ECF4803B0FCE38100A8A0BFA10768DACFF974CDDAC13C410E6893EB5C2905A06B8E3398BA7FECC1783D4C64F5C9D8C8A4EF3E764DD
        pkey[1]: 11
        keyid: A8146C0D28FB889F
    # off=265 ctb=88 tag=2 hlen=2 plen=92
    :signature packet: algo 1, keyid E8F4828E743BD5F3
        version 4, created 1587839289, md5len 0, sigclass 0x18
        digest algo 8, begin of digest 84 26
        hashed subpkt 2 len 4 (sig created 2020-04-25)
        subpkt 16 len 8 (issuer key ID E8F4828E743BD5F3)
        data: 869FE8EF31F27B60AED41D9A12C2DDA0933E1A29587D6E1BE2CE6108638262D31166E6731627223ED24E391675F5E20C73BAA63A8A822E9673A54B5344C06689
    # off=359 ctb=b8 tag=14 hlen=2 plen=75
    :public sub key packet:
        version 4, algo 1, created 1587839289, expires 0
        pkey[0]: AD91DEC826ED21DC4E759C84BE73CA1C07C64A5CC10E8A195B7ADACFE912F05F8F64CC63404BC2B3D39F9C675D59470208A66A7122626396C23AE6319F9E37F3
        pkey[1]: 11
        keyid: 870E6E023A933FB5
    # off=436 ctb=88 tag=2 hlen=2 plen=92
    :signature packet: algo 1, keyid E8F4828E743BD5F3
        version 4, created 1587839289, md5len 0, sigclass 0x18
        digest algo 8, begin of digest d9 a4
        hashed subpkt 2 len 4 (sig created 2020-04-25)
        subpkt 16 len 8 (issuer key ID E8F4828E743BD5F3)
        data: A1D8E93E45D3DB934775F96E005CB5C06AA2D17B56B73DC77DD71B1A9957558015C8CDFA6707AB8CDB18D72C339740757B64269A528FAD971EA64FFAFD4CE945

**After cross-certification**: `data/cross-certified-public-keyring.lst`

    # off=0 ctb=98 tag=6 hlen=2 plen=75
    :public key packet:
        version 4, algo 1, created 1587839289, expires 0
        pkey[0]: A60F07AEBA2CAFB169645750E1186A082B466E9B130D260252E87B003C3903B32EA03C27E4585CDDE153B139B8B3A1495C67E1113771C7E84B049A6305B6A341
        pkey[1]: 11
        keyid: E8F4828E743BD5F3
    # off=77 ctb=b4 tag=13 hlen=2 plen=15
    :user ID packet: "owner@email.com"
    # off=94 ctb=88 tag=2 hlen=2 plen=92
    :signature packet: algo 1, keyid E8F4828E743BD5F3
        version 4, created 1587839289, md5len 0, sigclass 0x13
        digest algo 8, begin of digest 49 4f
        hashed subpkt 2 len 4 (sig created 2020-04-25)
        subpkt 16 len 8 (issuer key ID E8F4828E743BD5F3)
        data: 7A0CA4D3A272AC30A9288BDFD6D9FC13858E4B4477B2F00AFB9A3E8604C0DF361BAA7A3DDF0CCDA4F6A3F95727EFA803F1CEEE45500A4CC0300E2E4493B546BC
    # off=188 ctb=b8 tag=14 hlen=2 plen=75
    :public sub key packet:
        version 4, algo 1, created 1587839289, expires 0
        pkey[0]: CB5596CEF89C6BD5C284C0ECF4803B0FCE38100A8A0BFA10768DACFF974CDDAC13C410E6893EB5C2905A06B8E3398BA7FECC1783D4C64F5C9D8C8A4EF3E764DD
        pkey[1]: 11
        keyid: A8146C0D28FB889F
    # off=265 ctb=88 tag=2 hlen=2 plen=232
    :signature packet: algo 1, keyid E8F4828E743BD5F3
        version 4, created 1587839494, md5len 0, sigclass 0x18
        digest algo 8, begin of digest 2c c7
        hashed subpkt 33 len 21 (issuer fpr v4 A2E076C534FAB58BD33822ACE8F4828E743BD5F3)
        hashed subpkt 2 len 4 (sig created 2020-04-25)
        subpkt 32 len 115 (signature: v4, class 0x19, algo 1, digest algo 8)
        subpkt 16 len 8 (issuer key ID E8F4828E743BD5F3)
        data: 506F88E1D15F3DB56AE986670DE20E29F2B5A3A5D113F206AC93DD06AE250E18B626DE3D58F9291BEF6D152A7A5F6EF66D399E0A585AB04EF3BFA1B2B42E9C4D
    # off=499 ctb=b8 tag=14 hlen=2 plen=75
    :public sub key packet:
        version 4, algo 1, created 1587839289, expires 0
        pkey[0]: AD91DEC826ED21DC4E759C84BE73CA1C07C64A5CC10E8A195B7ADACFE912F05F8F64CC63404BC2B3D39F9C675D59470208A66A7122626396C23AE6319F9E37F3
        pkey[1]: 11
        keyid: 870E6E023A933FB5
    # off=576 ctb=88 tag=2 hlen=2 plen=232
    :signature packet: algo 1, keyid E8F4828E743BD5F3
        version 4, created 1587839494, md5len 0, sigclass 0x18
        digest algo 8, begin of digest e6 84
        hashed subpkt 33 len 21 (issuer fpr v4 A2E076C534FAB58BD33822ACE8F4828E743BD5F3)
        hashed subpkt 2 len 4 (sig created 2020-04-25)
        subpkt 32 len 115 (signature: v4, class 0x19, algo 1, digest algo 8)
        subpkt 16 len 8 (issuer key ID E8F4828E743BD5F3)
        data: 8E95E81C8DEFE8B7C38D7E0AF368DEF109B7FB501492E80DCD2A9B3B9D2E3887B2E32C1D809ECF2000A22B179783E4F152396397BFCBC97128FF8EEE1F0013E7
	
Now, let's compare the signatures for the sub-key `A8146C0D28FB889F`.
	
Before "cross-certification":

    # off=265 ctb=88 tag=2 hlen=2 plen=92
    :signature packet: algo 1, keyid E8F4828E743BD5F3
        version 4, created 1587839289, md5len 0, sigclass 0x18
        digest algo 8, begin of digest 84 26
        hashed subpkt 2 len 4 (sig created 2020-04-25)
        subpkt 16 len 8 (issuer key ID E8F4828E743BD5F3)
        data: 869FE8EF31F27B60AED41D9A12C2DDA0933E1A29587D6E1BE2CE6108638262D31166E6731627223ED24E391675F5E20C73BAA63A8A822E9673A54B5344C06689

After "cross-certification":

    # off=265 ctb=88 tag=2 hlen=2 plen=232
    :signature packet: algo 1, keyid E8F4828E743BD5F3
        version 4, created 1587839494, md5len 0, sigclass 0x18
        digest algo 8, begin of digest 2c c7
        hashed subpkt 33 len 21 (issuer fpr v4 A2E076C534FAB58BD33822ACE8F4828E743BD5F3)
        hashed subpkt 2 len 4 (sig created 2020-04-25)
        subpkt 32 len 115 (signature: v4, class 0x19, algo 1, digest algo 8)
        subpkt 16 len 8 (issuer key ID E8F4828E743BD5F3)
        data: 506F88E1D15F3DB56AE986670DE20E29F2B5A3A5D113F206AC93DD06AE250E18B626DE3D58F9291BEF6D152A7A5F6EF66D399E0A585AB04EF3BFA1B2B42E9C4D

* `version 4`: [Version 4 Signature Packet Format](https://tools.ietf.org/html/rfc4880#section-5.2.3)
* `digest algo 8`: [SHA256](https://tools.ietf.org/html/rfc4880#section-9.4)
* `subpkt 33`: [The signing-key's fingerprint prepended by '0x04'](https://lists.gnupg.org/pipermail/gnupg-users/2018-January/059881.html).
* `subpkt 2`: [Signature Creation Time](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)
* `subpkt 32`: [Embedded Signature](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)
* `subpkt 16`: [Issuer](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)

We can see what has been added to the sub-key:

        hashed subpkt 33 len 21 (issuer fpr v4 A2E076C534FAB58BD33822ACE8F4828E743BD5F3)
        subpkt 32 len 115 (signature: v4, class 0x19, algo 1, digest algo 8)

* `subpkt 32`: [Embedded Signature](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)
  * `class 0x19`: [primary key binding signature or back signature](https://tools.ietf.org/html/rfc4880#section-11.1)
* `subpkt 33`: [The signing-key's fingerprint prepended by '0x04'](https://lists.gnupg.org/pipermail/gnupg-users/2018-January/059881.html).

From [RFC4880 section-5.2.1](https://tools.ietf.org/html/rfc4880#section-5.2.1):

> **0x19**: Primary Key Binding Signature.
> This signature is a statement by a signing subkey, indicating
> that it is owned by the primary key and subkey.  This signature
> is calculated the same way as a 0x18 signature: directly on the
> primary key and subkey, **and not on any User ID or other packets**.

From [FRC4880 section-11.1](https://tools.ietf.org/html/rfc4880#section-11.1):

> Each Subkey packet MUST be followed by one Signature packet, which
> should be a subkey binding signature issued by the top-level key.
> For subkeys that can issue signatures, the subkey binding signature
> MUST contain an Embedded Signature subpacket with a primary key
> binding signature (0x19) issued by the subkey on the top-level key.

From [RFC4880 section-15](https://tools.ietf.org/html/rfc4880#section-15):

> The **0x19** back signatures were not required for signing subkeys
> until relatively recently.  Consequently, there may be keys in
> the wild that do not have these back signatures.  Implementing
> software may handle these keys as it sees fit.
