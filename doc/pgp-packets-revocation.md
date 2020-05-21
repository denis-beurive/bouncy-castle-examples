# Master/Sub key revocation

There are two kinds of revocations:
* the revocation of a master key.
* the revocation of a subkey.

Both kinds of revocations imply the same type of packet:
a [Subkey Revocation Signature Packet](https://tools.ietf.org/html/rfc4880#section-5.2.1) (tag=2, type=0x28).

However, what we call a "revocation certificate" differs greatly depending on the type of key being revoked.
* the revocation certificate for a master key is a document that contains a single packet: a [Subkey Revocation Signature Packet](https://tools.ietf.org/html/rfc4880#section-5.2.1).
* the revocation certificate for a subkey is a document that represents a keyring with an inserted [Subkey Revocation Signature Packet](https://tools.ietf.org/html/rfc4880#section-5.2.1) just after the packet that represents the [Public-Subkey Packet](https://tools.ietf.org/html/rfc4880#section-5.5.1.2) the represents the subkey to revoke.
  Click [here](pgp-packets-subkey-revocation-certificate/after-revocation.txt) to see the structure of such a subkey revocation certificate.

> [This **excellent** link](https://blogs.gentoo.org/mgorny/2019/02/20/gen-revoke-extending-revocation-certificates-to-subkeys/) gives a pretty good explanation of the reason why there is such a difference between the two kinds of revocation certificates:
>
> One specific type of signatures are revocation signatures. Those signatures indicate that the relevant key, subkey or UID has been revoked. If a revocation signature is found, it takes precedence over any other kinds of signatures and prevents the revoked object from being further used.
>
> Key updates are means of distributing new data associated with the key. What’s important is that during an update the key is not replaced by a new one. Instead, GnuPG collects all the new data (subkeys, UIDs, signatures) and adds it to the local copy of the key. The validity of this data is verified against appropriate signatures. Appropriately, anyone can submit a key update to the keyserver, provided that the new data includes valid signatures. Similarly to local GnuPG instance, the keyserver is going to update its copy of the key rather than replacing it.
>
> Revocation certificates specifically make use of this property. Technically, a revocation certificate is simply an exported form of a revocation signature, signed using the owner’s primary key. As long as it’s not on the key (i.e. GnuPG does not see it), it does not do anything. When it’s imported, GnuPG adds it to the key. Further submissions and exports include it, effectively distributing it to all copies of the key. 

GPG procedures:

* click on [this link](pgp-packets-key-revocation-certicate.md) to get the procedure used with GPG to generate a revocation certificate for a master key.
* click on [this link](pgp-packets-subkey-revocation-certificate.md) to get the procedure used with GPG to generate a revocation certificate for a subkey.
