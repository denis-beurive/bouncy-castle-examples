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

> [This link](https://blogs.gentoo.org/mgorny/2019/02/20/gen-revoke-extending-revocation-certificates-to-subkeys/) gives a pretty good explanation of the reason why there is such a difference between the two kinds of revocation certificates.

GPG procedures:

* click on [this link](pgp-packets-key-revocation-certicate.md) to get the procedure used with GPG to generate a revocation certificate for a master key.
* click on [this link](pgp-packets-subkey-revocation-certificate.md) to get the procedure used with GPG to generate a revocation certificate for a subkey.
