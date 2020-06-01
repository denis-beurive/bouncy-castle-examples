# 0x28: Subkey revocation signature

> 0x28 = 40

> The signature is calculated directly on the subkey being revoked.
> A revoked subkey is not to be used.  Only revocation signatures
> by the top-level signature key that is bound to this subkey, or
> by an authorized revocation key, should be considered valid
> revocation signatures.

See [Anatomy of a subkey revocation certificate](../pgp-packets-subkey-revocation-certificate.md)

This signature indicates that a subkey is being revoked.
It looks like:

    # off=1491 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid D6B21BFAAD1A9DE0
        version 4, created 1590084900, md5len 0, sigclass 0x28
        digest algo 8, begin of digest 07 d1
        hashed subpkt 33 len 21 (issuer fpr v4 0C91C3D0E5C1CD015EFBD00DD6B21BFAAD1A9DE0)
        hashed subpkt 2 len 4 (sig created 2020-05-21)
        hashed subpkt 29 len 1 (revocation reason 0x00 ())
        subpkt 16 len 8 (issuer key ID D6B21BFAAD1A9DE0)
        data: [2048 bits]

Please note that is key ID of the issuer always identifies the master/primary key bound to the subkey being revoked.
In the example above, `D6B21BFAAD1A9DE0` refers to the master/primary key bound to the subkey being revoked.
Indeed, only master/primary keys can issue certificates.

> See[Key Structures](https://tools.ietf.org/html/rfc4880#section-12.1) In a V4 key, **the primary key MUST
> be a key capable of certification**. The subkeys may be keys of any **other type**.
