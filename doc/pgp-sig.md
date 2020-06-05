# PGP signature types

| Hex  | Dec | Name                                                       | Self Sig |
|------|-----|------------------------------------------------------------|----------|
| 0x00 | 0   | Signature of a binary document                             |          |
| 0x01 | 1   | Signature of a canonical text document                     |          |
| 0x02 | 2   | Standalone signature                                       |          |
| 0x10 | 16  | Generic certification of a User ID and Public-Key packet   | x        |
| 0x11 | 17  | Persona certification of a User ID and Public-Key packet   | x        |
| 0x12 | 18  | Casual certification of a User ID and Public-Key packet    | x        |
| 0x13 | 19  | Positive certification of a User ID and Public-Key packet  | x        |
| 0x18 | 24  | Subkey Binding Signature                                   | x        |
| 0x19 | 25  | Primary Key Binding Signature                              |          |
| 0x1F | 31  | Signature directly on a key                                | x        |
| 0x20 | 32  | Key revocation signature                                   |          |
| 0x28 | 40  | Subkey revocation signature                                |          |
| 0x30 | 48  | Certification revocation signature                         |          |
| 0x40 | 64  | Timestamp signature                                        |          |
| 0x50 | 80  | Third-Party Confirmation signature                         |          |

* [0x00: Signature of a binary document](pgp-sig/sig-of-a-binarydocument.md)
* [0x01: Signature of a canonical text document](pgp-sig/sig-of-a-canonical-text-document.md)
* [0x02: Standalone signature](pgp-sig/sig-standalone.md)
* [0x10: Generic certification of a User ID and Public-Key packet](pgp-sig/sig-generic-certification-of-a-user-id-and-public-key-packet.md)
* [0x11: Persona certification of a User ID and Public-Key packet](pgp-sig/sig-persona-certification-of-a-user-id-and-public-key-packet.md)
* [0x12: Casual certification of a User ID and Public-Key packet](pgp-sig/sig-casual-certification-of-a-user-id-and-public-key-packet.md)
* [0x13: Positive certification of a User ID and Public-Key packet](pgp-sig/sig-positive-certification-of-a-user-id-and-public-key-packet.md)
* [0x18: Subkey Binding Signature](pgp-sig/sig-subkey-binding-signature.md)
* [0x19: Primary Key Binding Signature](pgp-sig/sig-primary-key-binding-signature.md)
* [0x1F: Signature directly on a key](pgp-sig/sig-directly-on-a-key.md)
* [0x20: Key revocation signature](pgp-sig/sig-key-revocation-signature.md)
* [0x28: Subkey revocation signature](pgp-sig/sig-subkey-revocation-signature.md)
* [0x30: Certification revocation signature](pgp-sig/sig-certification-revocation-signature.md)
* [0x40: Timestamp signature](pgp-sig/sig-timestamp-signature.md)
* [0x50: Third-Party Confirmation signature](pgp-sig/sig-third-party-confirmation-signature.md)

Notes:
* [RFC 4880: Notes on Self-Signatures](https://tools.ietf.org/html/rfc4880#section-5.2.3.3) (0x10, 0x11, 0x12, 0x13, 0x1F, 0x18).

