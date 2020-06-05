# PGP signature types

| Hex  | Dec | Name                                                                                                                                  | Self Sig | Cert Sig | /User | /Key |
|------|-----|---------------------------------------------------------------------------------------------------------------------------------------|----------|----------|-------|------|
| 0x00 | 0   | [Signature of a binary document](pgp-sig/sig-of-a-binarydocument.md)                                                                  |          |          |       |      |
| 0x01 | 1   | [Signature of a canonical text document](pgp-sig/sig-of-a-canonical-text-document.md)                                                 |          |          |       |      |
| 0x02 | 2   | [Standalone signature](pgp-sig/sig-standalone.md)                                                                                     |          |          |       |      |
| 0x10 | 16  | [Generic certification of a User ID and Public-Key packet](pgp-sig/sig-generic-certification-of-a-user-id-and-public-key-packet.md)   | x        | x        | x     |      |
| 0x11 | 17  | [Persona certification of a User ID and Public-Key packet ](pgp-sig/sig-persona-certification-of-a-user-id-and-public-key-packet.md)  | x        | x        | x     |      |
| 0x12 | 18  | [Casual certification of a User ID and Public-Key packet](pgp-sig/sig-casual-certification-of-a-user-id-and-public-key-packet.md)     | x        | x        | x     |      |
| 0x13 | 19  | [Positive certification of a User ID and Public-Key packet](pgp-sig/sig-positive-certification-of-a-user-id-and-public-key-packet.md) | x        | x        | x     |      |
| 0x18 | 24  | [Subkey Binding Signature](pgp-sig/sig-subkey-binding-signature.md)                                                                   | x        |          |       | x    |
| 0x19 | 25  | [Primary Key Binding Signature](pgp-sig/sig-primary-key-binding-signature.md)                                                         |          |          |       |      |
| 0x1F | 31  | [Signature directly on a key](pgp-sig/sig-directly-on-a-key.md)                                                                       | x        |          |       | x    |
| 0x20 | 32  | [Key revocation signature](pgp-sig/sig-key-revocation-signature.md)                                                                   |          |          |       |      |
| 0x28 | 40  | [Subkey revocation signature](pgp-sig/sig-subkey-revocation-signature.md)                                                             |          |          |       |      |
| 0x30 | 48  | [Certification revocation signature](pgp-sig/sig-certification-revocation-signature.md)                                               |          |          |       |      |
| 0x40 | 64  | [Timestamp signature](pgp-sig/sig-timestamp-signature.md)                                                                             |          |          |       |      |
| 0x50 | 80  | [Third-Party Confirmation signature](pgp-sig/sig-third-party-confirmation-signature.md)                                               |          |          |       |      |

> **Self Sig**: Self signature. See [Notes on Self-Signatures](https://tools.ietf.org/html/rfc4880#section-5.2.3.3):
> A self-signature is a binding signature made by the key to which the signature refers.

> **Cert sig**: Certification Signature (also called "Endorsing Signature" or "Key Signature").
> See [RFC 4880: Computing Signatures](https://tools.ietf.org/html/rfc4880#section-5.2.4): a
> certification signature (type `0x10` through `0x13`) hashes the User ID being bound to the key
> into the hash context after the above data.

When _certification signatures_ (type `0x10` through `0x13`) are used as self signatures,
they are called _certification self signatures_. 

Notes:
* [RFC 4880: Computing Signatures](https://tools.ietf.org/html/rfc4880#section-5.2.4)
* [RFC 4880: Notes on Self-Signatures](https://tools.ietf.org/html/rfc4880#section-5.2.3.3) (0x10, 0x11, 0x12, 0x13, 0x1F, 0x18).
