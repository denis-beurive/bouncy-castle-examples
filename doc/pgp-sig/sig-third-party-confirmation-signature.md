# 0x50: Third-Party Confirmation signature

> 0x50 = 80

> This signature is a signature over some other OpenPGP Signature
> packet(s).  It is analogous to a notary seal on the signed data.
> A third-party signature SHOULD include _Signature Target
> subpacket(s)_ to give easy identification.  Note that we really do
> mean SHOULD.  There are plausible uses for this (such as a blind
> party that only sees the signature, not the key or source
> document) that cannot include a target subpacket.

Note about [Signature Target Subpacket (type=31)](https://tools.ietf.org/html/rfc4880#section-5.2.3.25):

> This subpacket identifies a specific target signature to which a
> signature refers.  For revocation signatures, this subpacket
> provides explicit designation of which signature is being revoked.
> For a third-party or timestamp signature, this designates what
> signature is signed.  All arguments are an identifier of that target
> signature.

However, at the time these lines are written, GPG does not support this kind of signature.

See [Third-Party Confirmation signature?](https://lists.gnutls.org/pipermail/gnupg-users/2019-July/062318.html).

