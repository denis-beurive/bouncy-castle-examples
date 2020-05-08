# Third packet

`0x88`: `0b10001000`

* [format](https://tools.ietf.org/html/rfc4880#section-4.2.1): old
* [tag](https://tools.ietf.org/html/rfc4880#section-4.3): `0b0010` = `2` => Signature Packet 
* [type](https://tools.ietf.org/html/rfc4880#section-4.2.1): `0b00` = `0` => The packet has a one-octet length.
  The header is 2 octets long.  
* length = `0x9C` = 156 bytes.

body:

    04 10 01 08 00 06 05 02 5E B2 CE 3B 00 0A 09 10
    EF C8 52 09 1E 95 E7 5C 68 B3 04 00 AF 1B AF 3C
    56 9C DA 34 AC D0 7D D0 7E 28 50 DF C4 9B 89 A6
    C1 40 2D AA 5D 99 79 56 B2 01 14 2B 1D DF 5C A9
    C4 B1 05 A6 3F 09 9E 64 71 B9 71 20 D7 10 D3 51
    9B 95 41 C7 C0 E0 F6 5B 62 07 34 87 89 82 9D 98
    7C D8 9A 25 3F 34 29 44 20 07 47 71 95 05 5E 5C
    C1 10 39 78 05 A5 D6 20 17 66 5D 88 84 66 38 69
    44 E5 2E BB 1A 8F C5 CA DE C5 08 69 84 BB 23 AC
    51 16 F4 1A D8 56 C3 CA 5F 17 78 C7

[Signature Packet](https://tools.ietf.org/html/rfc4880#section-5.2)

> A Signature packet describes a binding between some **public key** and some data.
> ...
> Two versions of Signature packets are defined.  Version 3 provides
> basic signature information, while version 4 provides an expandable
> format with subpackets that can specify more information about the
> signature.

* First byte: `0x04` => [Version 4 Signature Packet Format](https://tools.ietf.org/html/rfc4880#section-5.2.3)
* Second byte: `0x10` => [Generic certification of a User ID and Public-Key packet.](https://tools.ietf.org/html/rfc4880#section-5.2.1)
* Third byte: `0x01` => [RSA (Encrypt or Sign)](https://tools.ietf.org/html/rfc4880#section-9.1)
* Fourth byte: `0x08` => [SHA256](https://tools.ietf.org/html/rfc4880#section-9.4)
* Octet count for following hashed subpacket data: `0x0006` = `6` bytes. _This is the length in octets of
  **all of the hashed subpackets**; a pointer incremented by this number will skip over the hashed subpackets_.
  
## Hashed subpacket data

[Signature Subpacket Specification](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)

> Each subpacket consists of a subpacket header and a body.  The header consists of:
> * the subpacket length (1, 2, or 5 octets),
> * the subpacket type (1 octet),
>
> And is followed by the subpacket-specific data.

First (and unique) hashed bubpacket:

![](images/subpacket-signature-creation-time.svg)

* First byte: `0x05` = `5`. `5 < 192` => the length of the subpacket is coded on one byte - _this byte_.
  Thus, the length of the subpacket is **5 bytes**. It includes the type byte (that follows), but not _this byte_.
  Thus, the lentgh of the subpacket body is `5-1 = 4` bytes.
* Type: `0x02` = `2` => [Signature Creation Time](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)
* Packet body: `0x5EB2CE3B` = `1588776507` => Wednesday 6 May 2020 14:48:27 [GMT]

> Please note that the total length of the hashed subpacket data is 6 bytes.

Next, we have the unhashed subpacket data (see [Version 4 Signature Packet Format](https://tools.ietf.org/html/rfc4880#section-5.2.3)).

## Unhashed subpacket data

[Signature Subpacket Specification](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)

* Two-octet scalar octet count for the following unhashed subpacket data: `0x0A` = `10` bytes.
  this is the length in octets of all of the unhashed subpackets; a pointer incremented by
  this number will skip over the unhashed subpackets.

First (and unique) unhashed bubpacket:

![](images/subpacket-issuer.svg)

* First byte: `0x09` = `9` => the length of the subpacket is coded on one byte - _this byte_.
  Thus, the length of the subpacket is **9 bytes**. It includes the type byte (that follows), but not _this byte_.
  Thus, the lentgh of the subpacket body is `9-1 = 8` bytes.
* Type: `0x10` = `16` => [Issuer](https://tools.ietf.org/html/rfc4880#section-5.2.3.1).

> Please note that the total length of the unhashed subpacket data is 10 bytes.

Next comes the signature (see [Version 4 Signature Packet Format](https://tools.ietf.org/html/rfc4880#section-5.2.3)).

## The signature

[Signature Subpacket Specification](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)

* Two-octet field holding the left 16 bits of the signed hash value: `0x68B3`.

Next: One or more multiprecision integers comprising the signature. This portion is algorithm specific.

See [Version 3 Signature Packet Format](https://tools.ietf.org/html/rfc4880#section-5.2.2):

The signature algorithm is RSA.

> Algorithm-Specific Fields for RSA signatures:
> * multiprecision integer (MPI) of RSA signature value m**d mod n.

[multiprecision integer (MPI)](https://tools.ietf.org/html/rfc4880#section-3.2):

> An MPI consists of two pieces: a two-octet scalar that is the length
> of the MPI in bits followed by a string of octets that contain the
> actual integer.

* two-octet scalar that is the length of the MPI in bits: `0x0400` = `1024` bits = `128`bytes.

MPI (1024 bits / 128 bytes):

    AF 1B AF 3C 56 9C DA 34 AC D0 7D D0 7E 28 50 DF
    C4 9B 89 A6 C1 40 2D AA 5D 99 79 56 B2 01 14 2B
    1D DF 5C A9 C4 B1 05 A6 3F 09 9E 64 71 B9 71 20
    D7 10 D3 51 9B 95 41 C7 C0 E0 F6 5B 62 07 34 87
    89 82 9D 98 7C D8 9A 25 3F 34 29 44 20 07 47 71
    95 05 5E 5C C1 10 39 78 05 A5 D6 20 17 66 5D 88
    84 66 38 69 44 E5 2E BB 1A 8F C5 CA DE C5 08 69
    84 BB 23 AC 51 16 F4 1A D8 56 C3 CA 5F 17 78 C7
