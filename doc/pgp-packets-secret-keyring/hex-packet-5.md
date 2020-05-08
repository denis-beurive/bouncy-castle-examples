# Fifth packet

`0x88`: `0b10001000`

* [format](https://tools.ietf.org/html/rfc4880#section-4.2.1): old
* [tag](https://tools.ietf.org/html/rfc4880#section-4.3): `0b0010` = `2` => Signature Packet 
* [type](https://tools.ietf.org/html/rfc4880#section-4.2.1): `0x00` = `0` => The packet has a one-octet length.
  The header is 2 octets long. 
* length = `0x9C` = 156 bytes 

body:

    04 18 01 08 00 06 05 02 5E B2 CE 3B 00 0A 09 10
    EF C8 52 09 1E 95 E7 5C 79 42 03 FD 1D A7 23 C8
    44 29 B3 34 97 78 A1 F3 CD 14 FB 96 8C 65 B0 0C
    2C 66 96 8F 9C 83 F9 47 FB E0 9D EE 36 AD F8 2B
    E5 E4 77 53 BB FA C0 66 EB 80 40 9E F8 36 11 E3
    AF 6F AF C9 88 A5 4C 29 AD C7 86 0F 24 22 11 E1
    C7 ED A6 1C 98 C2 43 18 9F A4 94 D3 E0 7D BD C9
    89 B1 E8 72 44 2F 9F 23 2A BD 81 E8 13 53 5F 47
    E6 C7 9E 31 6D 99 5B 5F FF D1 F5 E9 C2 44 28 F8
    E4 FC 2B 28 EA 85 32 A0 42 27 D6 18

[Signature Packet](https://tools.ietf.org/html/rfc4880#section-5.2)

> A Signature packet describes a binding between some public key and some data. ... Two versions of Signature packets are defined. Version 3 provides basic signature information, while version 4 provides an expandable format with subpackets that can specify more information about the signature.

* First byte: `0x04` => [Version 4 Signature Packet Format](https://tools.ietf.org/html/rfc4880#section-5.2.3)
* Second byte: `0x18` => [Subkey Binding Signature](https://tools.ietf.org/html/rfc4880#section-5.2.1)
* Third byte: `0x01` => [RSA (Encrypt or Sign)](https://tools.ietf.org/html/rfc4880#section-9.1)
* Fourth byte: `0x08` => [SHA256](https://tools.ietf.org/html/rfc4880#section-9.4)
* Octet count for following hashed subpacket data: `0x0006` = `6` bytes. _This is the length in octets of
  **all of the hashed subpackets**; a pointer incremented by this number will skip over the hashed subpackets_.

> Subkey Binding Signature (0x18):
>
> This signature is a statement by the top-level signing key that
> indicates that it owns the subkey.  This signature is calculated
> directly on the primary key and subkey, and **not on any User ID or
> other packets**.  A signature that binds a signing subkey MUST have
> an Embedded Signature subpacket in this binding signature that
> contains a 0x19 signature made by the signing subkey on the
> primary key and subkey.

## Hashed subpacket data

[Signature Subpacket Specification](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)

    Each subpacket consists of a subpacket header and a body. The header consists of:

    * the subpacket length (1, 2, or 5 octets),
    * the subpacket type (1 octet),
    
    And is followed by the subpacket-specific data.

First (and unique) hashed bubpacket:

![](images/subpacket-signature-creation-time.svg)

* First byte: `0x05` = `5`. `5 < 192` => the length of the subpacket is coded on one byte
  - this byte. Thus, the length of the subpacket is 5 bytes. It includes the type byte (that follows),
  but not this byte. Thus, the lentgh of the subpacket body is `5-1 = 4` bytes.
* Type: `0x02` = `2` => [Signature Creation Time](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)
* Packet body: `0x05EB2CE3B` => `1588776507` => Wednesday 6 May 2020 14:48:27 [GMT]

Next, we have the unhashed subpacket data (see [Version 4 Signature Packet Format](https://tools.ietf.org/html/rfc4880#section-5.2.3)).

## Unhashed subpacket data

[Signature Subpacket Specification](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)

* Two-octet scalar octet count for the following unhashed subpacket data: `0x0A` = `10`
  bytes. this is the length in octets of all of the unhashed subpackets; a pointer
  incremented by this number will skip over the unhashed subpackets.

![](images/subpacket-issuer.svg)

* First byte: `0x09` = `9` => the length of the subpacket is coded on one byte - _this byte_.
  Thus, the length of the subpacket is 9 bytes. It includes the type byte (that follows), but
  not this byte. Thus, the lentgh of the subpacket body is `9-1` = `8` bytes.
* Type: `0x10` = `16` => Issuer.

> Please note that the total length of the unhashed subpacket data is 10 bytes.

Next comes the signature (see [Version 4 Signature Packet Format](https://tools.ietf.org/html/rfc4880#section-5.2.3)).

## The signature

[Signature Subpacket Specification](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)

* Two-octet field holding the left 16 bits of the signed hash value: `0x7942`.

Next: One or more multiprecision integers comprising the signature. This portion is algorithm specific.

See [Version 3 Signature Packet Format](https://tools.ietf.org/html/rfc4880#section-5.2.2):

The signature algorithm is RSA.

> Algorithm-Specific Fields for RSA signatures:
> * multiprecision integer (MPI) of RSA signature value m**d mod n.

[multiprecision integer (MPI)](https://tools.ietf.org/html/rfc4880#section-3.2):

> An MPI consists of two pieces: a two-octet scalar that is the length of the MPI in bits followed by a string of octets that contain the actual integer.

* Two-octet scalar that is the length of the MPI in bits: `0x03FD` = `1021` bits = `128` bytes.

MPI (1021 bits / 128 bytes):

    1D A7 23 C8 44 29 B3 34 97 78 A1 F3 CD 14 FB 96
    8C 65 B0 0C 2C 66 96 8F 9C 83 F9 47 FB E0 9D EE
    36 AD F8 2B E5 E4 77 53 BB FA C0 66 EB 80 40 9E
    F8 36 11 E3 AF 6F AF C9 88 A5 4C 29 AD C7 86 0F
    24 22 11 E1 C7 ED A6 1C 98 C2 43 18 9F A4 94 D3
    E0 7D BD C9 89 B1 E8 72 44 2F 9F 23 2A BD 81 E8
    13 53 5F 47 E6 C7 9E 31 6D 99 5B 5F FF D1 F5 E9
    C2 44 28 F8 E4 FC 2B 28 EA 85 32 A0 42 27 D6 18
