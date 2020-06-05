# 0x20: Key revocation signature

> The signature is calculated directly on the key being revoked.  A
> revoked key is not to be used.  Only revocation signatures by the
> key being revoked, or by an authorized revocation key, should be
> considered valid revocation signatures.
       
See [Anatomy of a master key revocation certificate](../pgp-packets-key-revocation-certicate.md)

This signature indicates that a master/primary key is being revoked.
It looks like:

    # off=0 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid 2F3DC8F2A29E5F10
            version 4, created 1590067573, md5len 0, sigclass 0x20
            digest algo 8, begin of digest 43 98
            hashed subpkt 33 len 21 (issuer fpr v4 ADA313C0C49DDD87B075E9802F3DC8F2A29E5F10)
            hashed subpkt 2 len 4 (sig created 2020-05-21)
            hashed subpkt 29 len 1 (revocation reason 0x00 ())
            subpkt 16 len 8 (issuer key ID 2F3DC8F2A29E5F10)
            data: [2047 bits]

Please note that is key ID of the issuer always identifies the master/primary key itself.
In the example above, `2F3DC8F2A29E5F10` refers to the master/primary key itself.
Indeed, only master/primary keys can issue certificates.

> See[Key Structures](https://tools.ietf.org/html/rfc4880#section-12.1) In a V4 key, **the primary key MUST
> be a key capable of certification**. The subkeys may be keys of any **other type**.
