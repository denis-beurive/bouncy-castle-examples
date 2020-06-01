# Notes about signature subpacket

[Signature Subpacket Specification](https://tools.ietf.org/html/rfc4880#section-5.2.3.1):

> Two versions of Signature packets are defined.  **Version 3 provides
> basic signature information, while version 4 provides an expandable
> format with subpackets that can specify more information about the
> signature**.  _PGP 2.6.x only accepts version 3 signatures_.
>
> Implementations SHOULD accept V3 signatures. **Implementations SHOULD
> generate V4 signatures**.

Subpackets only make sense with PGP signature version 4.

[Signature Subpacket Specification](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)
shows the various types of subpackets:

>              0 = Reserved
>              1 = Reserved
>              2 = Signature Creation Time
>              3 = Signature Expiration Time
>              4 = Exportable Certification
>              5 = Trust Signature
>              6 = Regular Expression
>              7 = Revocable
>              8 = Reserved
>              9 = Key Expiration Time
>             10 = Placeholder for backward compatibility
>             11 = Preferred Symmetric Algorithms
>             12 = Revocation Key
>             13 = Reserved
>             14 = Reserved
>             15 = Reserved
>             16 = Issuer
>             17 = Reserved
>             18 = Reserved
>             19 = Reserved
>             20 = Notation Data
>             21 = Preferred Hash Algorithms
>             22 = Preferred Compression Algorithms
>             23 = Key Server Preferences
>             24 = Preferred Key Server
>             25 = Primary User ID
>             26 = Policy URI
>             27 = Key Flags
>             28 = Signer's User ID
>             29 = Reason for Revocation
>             30 = Features
>             31 = Signature Target
>             32 = Embedded Signature
>     100 To 110 = Private or experimental


