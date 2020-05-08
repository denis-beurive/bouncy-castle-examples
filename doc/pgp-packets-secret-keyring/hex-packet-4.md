# Fourth packet

`0x9D`: `0x10011101`

* [format](https://tools.ietf.org/html/rfc4880#section-4.2.1): old
* [tag](https://tools.ietf.org/html/rfc4880#section-4.3): `0b0111` = `7` => Secret-Subkey Packet 
* [type](https://tools.ietf.org/html/rfc4880#section-4.2.1): `0b01` = `1` => The packet has a two-octet length.
  The header is 3 octets long.
* length = `0x0204` = 516 bytes

> A Secret-Subkey packet (tag 7) is the subkey analog of the [Secret
> Key packet](https://tools.ietf.org/html/rfc4880#section-5.5.3) and has
> exactly the same format.

body:

    04 5E B2 CE 3B 01 04 00 D7 43 8B D3 57 57 2A D0
    19 7B E4 94 62 1E 35 FC 71 3E DF 80 20 42 73 E2
    23 F0 52 12 C3 5F 7C C0 7E 23 2B B8 F8 C6 1D 78
    EF 6C 79 23 4A 36 99 14 63 83 57 B2 72 42 C2 8F
    62 86 15 B4 19 D5 08 81 7E 0B E2 02 DB DE 06 D8
    E3 19 AB B8 54 CC 0A 74 40 55 E3 5C 59 4D 0F 51
    91 36 63 3A 6F 1C F5 EF 9D 86 4F 0A 7D A5 39 FD
    1B 74 3A 05 29 FC 2B 9C EF 45 39 23 28 37 B3 4B
    A4 02 54 BF 27 D7 EC 13 00 05 11 FE 09 03 08 9F
    19 C8 66 F9 DF 00 F4 60 C5 92 FB AD 4E 62 40 06
    F2 22 66 77 1D 17 EA 6F 03 2B 64 67 54 99 30 42
    1C 97 7F 64 B2 F8 72 6E 47 BB 26 C6 6D 9E 71 44
    19 AC 12 2B 76 24 98 28 F5 87 8B 68 71 43 D1 6E
    AE 06 3D 24 28 2B D7 9A A3 25 67 80 61 B3 1C 9F
    00 E1 6F CC 31 73 AC 3A 8B 78 7B CA 33 A6 B9 D0
    BE CD 39 9C 25 6F 4F 65 CB AC 78 D3 36 ED 65 A3
    5B 8B 22 2A 32 B1 6A 4B 18 18 9C 84 DC 7D 75 06
    12 BA 74 67 B2 95 34 BE 5E 0C 32 4B A4 88 36 36
    32 11 C6 72 03 9E D6 17 51 DD 74 3D BA B8 B7 3E
    60 C4 F4 9A 27 36 16 6A A9 C6 CB 62 70 80 10 96
    C6 78 D4 32 77 78 48 23 A2 87 D4 F3 87 06 C6 0A
    95 16 8E 86 13 D3 31 99 95 12 1E 3A 36 03 B8 A6
    81 76 57 FE 79 79 A7 2A 67 CC C8 65 31 6E 3D DE
    46 6C 9D 33 86 0D 47 22 FE 5F 08 3E 36 B4 E9 C7
    E5 66 A4 49 BA 2C 15 2C 6E 7E B3 B7 84 A2 B1 A5
    5D AF 5E 9A 59 BF D3 1D 89 90 97 6C B5 4D 0A FA
    1A B3 57 7B 9A 38 63 D4 76 27 48 86 73 07 F9 4A
    56 9F B5 D3 DD E7 55 36 C9 E2 08 9F E0 ED E9 63
    EA 75 C3 1E F6 14 05 23 9D CF 10 B8 21 93 40 6F
    4C 54 2C 03 9E 9D 34 9F F4 55 02 7B 71 7E 54 7A
    05 68 F3 CE 1A 59 53 BF 5E EE 42 43 8E 4C 6A 12
    6B 07 DD E5 91 F3 C0 A0 35 67 59 08 31 A7 69 C7
    6D A2 7B 22

The [Secret-Subkey Packet](https://tools.ietf.org/html/rfc4880#section-5.5.1.4) starts with a [Public-Key Packet](https://tools.ietf.org/html/rfc4880#section-5.5.2).

**The Public Key Packet**:

* The first byte is `0x04` => [A version 4 packet](https://tools.ietf.org/html/rfc4880#section-5.5.2)
* A four-octet number denoting the time that the key was created: `0x5EB2CE3B` => `1588776507` => Wednesday 6 May 2020 14:48:27 [GMT]  
* A one-octet number denoting the public-key algorithm of this key: `0x01` => [RSA](https://tools.ietf.org/html/rfc4880#section-9.1).
* A series of multiprecision integers comprising the key material.

> Algorithm-Specific Fields for RSA public keys:
> * multiprecision integer (MPI) of RSA public modulus n;
> * MPI of RSA public encryption exponent e.

**First MPI**:

See [Multiprecision Integers](https://tools.ietf.org/html/rfc4880#section-3.2).

* a two-octet scalar that is the length of the MPI in bits: `0x0400` = `1024` bits = `128` bytes.

MPI (1024 bits / 128 bytes)

    D7 43 8B D3 57 57 2A D0 19 7B E4 94 62 1E 35 FC
    71 3E DF 80 20 42 73 E2 23 F0 52 12 C3 5F 7C C0
    7E 23 2B B8 F8 C6 1D 78 EF 6C 79 23 4A 36 99 14
    63 83 57 B2 72 42 C2 8F 62 86 15 B4 19 D5 08 81
    7E 0B E2 02 DB DE 06 D8 E3 19 AB B8 54 CC 0A 74
    40 55 E3 5C 59 4D 0F 51 91 36 63 3A 6F 1C F5 EF
    9D 86 4F 0A 7D A5 39 FD 1B 74 3A 05 29 FC 2B 9C
    EF 45 39 23 28 37 B3 4B A4 02 54 BF 27 D7 EC 13

**Second MPI**: 

* a two-octet scalar that is the length of the MPI in bits: 

See [Multiprecision Integers](https://tools.ietf.org/html/rfc4880#section-3.2).

* a two-octet scalar that is the length of the MPI in bits: `0x0005` = `5` bits = `1` byte.

MPI (5 bits / 1 byte):

    11
    
`0x11` = `0b00010001` = `17`

* One octet indicating string-to-key usage conventions: `0xFE` = `254`.
  255 or 254 indicates that a string-to-key specifier is being given.
* If string-to-key usage octet was 255 or 254, a one-octet symmetric encryption algorithm:
  `0x09` = `09` => [AES with 256-bit key](https://tools.ietf.org/html/rfc4880#section-9.4).
* If string-to-key usage octet was 255 or 254, a [string-to-key specifier](https://tools.ietf.org/html/rfc4880#section-3.7):
  * First byte: `0x03` = `3` => [Iterated and Salted S2K](https://tools.ietf.org/html/rfc4880#section-3.7.1.3).
  * Second byte: `0x08` = `8` => [SHA256](https://tools.ietf.org/html/rfc4880#section-9.4)
  * Bytes 2-9: 8-octet salt value = `9F 19 C8 66 F9 DF 00 F4`.
  * Byte 10: count, a one-octet, coded value = `0x60` = `96`
  
Use this C program to calculate the count:

    #include <stdio.h>
    #include <stdint.h>
    
    #define EXPBIAS 6
    
    int main() {
    
        int32_t c = 96;
        int32_t count = ((int32_t)16 + (c & 15)) << ((c >> 4) + EXPBIAS);
        printf("count = %d\n", count);
    }

=> count = 65536   

> Iterated-Salted S2K hashes the passphrase and salt data multiple times. The total number of octets to be hashed is specified in the encoded count in the S2K specifier. Note that the resulting count value is an octet count of how many octets will be hashed, not an iteration count.
  
* If secret data is encrypted (string-to-key usage octet not zero), an Initial
  Vector (IV) of the same length as the cipher's block size.

The cypher is [AES with 256-bit key](https://tools.ietf.org/html/rfc4880#section-9.2). The block size is: 128 bits (see wikipedia), 16 bytes.

Thus, the Initial Vector is: `C5 92 FB AD 4E 62 40 06 F2 22 66 77 1D 17 EA 6F`

* Plain or encrypted multiprecision integers comprising the secret key data.

> Algorithm-Specific Fields for RSA secret keys:
> * multiprecision integer (MPI) of RSA secret exponent d.
> * MPI of RSA secret prime value p.
> * MPI of RSA secret prime value q (p < q).
> * MPI of u, the multiplicative inverse of p, mod q.

The encrypted private key MPIs (encrypted with the 20-octet SHA-1 hash of the plaintext of the algorithm-specific portion):

    03 2B 64 67 54 99 30 42 1C 97 7F 64 B2 F8 72 6E
    47 BB 26 C6 6D 9E 71 44 19 AC 12 2B 76 24 98 28
    F5 87 8B 68 71 43 D1 6E AE 06 3D 24 28 2B D7 9A
    A3 25 67 80 61 B3 1C 9F 00 E1 6F CC 31 73 AC 3A
    8B 78 7B CA 33 A6 B9 D0 BE CD 39 9C 25 6F 4F 65
    CB AC 78 D3 36 ED 65 A3 5B 8B 22 2A 32 B1 6A 4B
    18 18 9C 84 DC 7D 75 06 12 BA 74 67 B2 95 34 BE
    5E 0C 32 4B A4 88 36 36 32 11 C6 72 03 9E D6 17
    51 DD 74 3D BA B8 B7 3E 60 C4 F4 9A 27 36 16 6A
    A9 C6 CB 62 70 80 10 96 C6 78 D4 32 77 78 48 23
    A2 87 D4 F3 87 06 C6 0A 95 16 8E 86 13 D3 31 99
    95 12 1E 3A 36 03 B8 A6 81 76 57 FE 79 79 A7 2A
    67 CC C8 65 31 6E 3D DE 46 6C 9D 33 86 0D 47 22
    FE 5F 08 3E 36 B4 E9 C7 E5 66 A4 49 BA 2C 15 2C
    6E 7E B3 B7 84 A2 B1 A5 5D AF 5E 9A 59 BF D3 1D
    89 90 97 6C B5 4D 0A FA 1A B3 57 7B 9A 38 63 D4
    76 27 48 86 73 07 F9 4A 56 9F B5 D3 DD E7 55 36
    C9 E2 08 9F E0 ED E9 63 EA 75 C3 1E F6 14 05 23
    9D CF 10 B8 21 93 40 6F 4C 54 2C 03 9E 9D 34 9F
    F4 55 02 7B 71 7E 54 7A 05 68 F3 CE 1A 59 53 BF
    5E EE 42 43 8E 4C 6A 12 6B 07 DD E5 91 F3 C0 A0
    35 67 59 08 31 A7 69 C7 6D A2 7B 22

The above block of bytes is encrypted. To get it, we selected the bytes knowing that:
* the total length of the packet is 516 bytes.
* the position of the last byte of the Initial Vector.

> **Please note**: If the string-to-key usage octet was
> 254, then a 20-octet SHA-1 hash of the plaintext of the
> algorithm-specific portion. **This checksum or hash is encrypted
> together with the algorithm-specific fields.**
> (see [Secret-Key Packet Formats](https://tools.ietf.org/html/rfc4880#section-5.5.3)) 
