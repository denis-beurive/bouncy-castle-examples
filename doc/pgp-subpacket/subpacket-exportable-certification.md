# (4) Exportable Certification

> This subpacket denotes whether a [certification signature](../pgp-sig.md) is
> "exportable", to be used by other users than the signature's issuer.

This subpacket only applies to certification signatures (_sigclass_ = `0x10`, `0x11`, `0x12` and `0x13`).

If the value of this subpacket states that the associated (certification) signature is not exportable, then this
(certification) signature will not be _exported_ with (the rest of) the key (for example, when you issue
the GPG command `gpg --export FD46A5EFC8368BBF`).

