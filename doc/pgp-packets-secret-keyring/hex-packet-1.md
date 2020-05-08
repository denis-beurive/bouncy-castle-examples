# First packet

`0x95`: `0b10010101`

* [format](https://tools.ietf.org/html/rfc4880#section-4.2.1): old
* [tag](https://tools.ietf.org/html/rfc4880#section-4.3): `0b0101` = `5` => Secret-Key Packet
* [type](https://tools.ietf.org/html/rfc4880#section-4.2.1): `0b01` = `1` => The packet has a two-octet length.
  The header is 3 octets long.
* length = `0x0204` = 516 bytes.

body: 

    04 5E B2 CE 3A 01 04 00 C5 08 AE 1F 60 C5 5B 73
    B7 C8 E8 CF D8 62 31 C0 48 2F C0 25 9E E9 13 48
    23 C4 0C 8B 29 B9 A2 5C 31 C4 8E 59 51 31 59 D3
    95 0F 74 69 ED 25 5C 4E EF B9 9A 7C 59 17 F3 1B
    24 84 46 39 EC 43 BA DB A6 7A BD F3 20 C2 59 92
    72 C5 DF E5 4C 0F 9D 75 5B DB 71 DF FA 48 F0 E0
    C6 46 2F 50 84 BD C8 6B 25 81 59 FF EE A1 BD 92
    2D 26 8C 5E 1B 95 06 4D F3 DB AD 89 D6 77 ED 12
    C1 BD 65 3B BE B5 8A 03 00 05 11 FE 09 03 08 9F
    19 C8 66 F9 DF 00 F4 60 70 EB 09 93 8C CF 0A BC
    FC 0F C9 60 C7 59 8E 46 1E 68 B2 A6 C8 9D 98 65
    B5 52 27 7F 2B EB 27 8E A0 6D FA 17 1D 28 50 19
    27 8A AC 33 AA 46 5B 31 AE 2C 3E 31 A2 4F 0E 86
    B3 4C 4E 9A 81 D3 43 BC B1 00 08 9A 98 F7 EE 47
    12 6E B8 25 00 CE 87 7E 84 E9 16 99 4F 00 7D 67
    02 FB 10 8C B9 AE EF 55 49 7E 47 34 1C 15 36 F2
    B5 F3 D5 01 31 AE AB F9 4B F1 8F 6C 6B 3B E5 8D
    4D D3 3D ED 0A F9 71 BD 9C 7F B6 1D 7E 46 0B 0D
    93 A2 FE EB 6F 2F 88 5C A0 F6 F0 9A 83 F8 2B D7
    AF BA C9 40 25 E3 60 5F 9A 7F D6 1A B3 50 C4 C2
    19 9A 4F 4F 74 92 53 9B 02 3E 35 92 70 B0 0C F2
    FD AD 70 24 67 00 00 42 82 AF 3A 56 7E 50 D3 9E
    26 25 03 42 5F 71 FE D8 6B 58 DD 97 6E E9 06 01
    FA 56 8B DE 37 E3 46 91 E4 56 62 8B 7C B3 14 08
    6C E5 26 ED D6 70 BD E7 42 BC AF 30 1A 07 88 C3
    86 36 6A B7 18 23 14 A8 5D 83 E8 BD 85 0A 19 41
    E3 EB 2A 85 16 0C F4 4D 0D 4E 9C 7B 48 41 58 91
    6C 5A 42 51 7D AA 2E 5C 1F B0 71 32 06 96 DB A6
    D5 2D 98 94 F1 69 64 5A DD 9D BC 6B 3E C8 CC 9F
    1D EB 43 34 EA 11 CA 16 71 E5 FA EB 33 EA 1B 0E
    45 BF F8 0A 23 B4 61 08 8D 31 4C 46 5F 31 29 E7
    38 61 0A 48 D7 F1 12 30 62 68 01 77 0C 08 A3 F5
    AB D5 B9 11

[Secret-Key Packet](https://tools.ietf.org/html/rfc4880#section-5.5.1.3)

* The public key comes first.
* Then the secret key follows.

## Public key material

See [Public-Key Packet Formats](https://tools.ietf.org/html/rfc4880#section-5.5.2):

* A one-octet version number (4).
* A four-octet number denoting the time that the key was created: `0x5EB2CE3A` (`1588776506`).
* A one-octet number denoting the public-key algorithm of this key: `0x01` (`1`) => [RSA](https://tools.ietf.org/html/rfc4880#section-9.1).
* A series of multiprecision integers comprising the key material.
  Algorithm-Specific Fields for RSA public keys:
  * [multiprecision integer (MPI)](https://tools.ietf.org/html/rfc4880#section-3.2) of RSA public modulus n;
  * [MPI](https://tools.ietf.org/html/rfc4880#section-3.2) of RSA public encryption exponent e.

> An MPI consists of two pieces: a two-octet scalar that is the length
> of the MPI in bits followed by a string of octets that contain the
> actual integer.

**First MPI**:

* length: `0x0400` = 1024 bits (128 bytes)
* integer: `C5 08 AE 1F 60 C5 5B 73 B7 C8 E8 CF D8 62 31 C0
            48 2F C0 25 9E E9 13 48 23 C4 0C 8B 29 B9 A2 5C
            31 C4 8E 59 51 31 59 D3 95 0F 74 69 ED 25 5C 4E
            EF B9 9A 7C 59 17 F3 1B 24 84 46 39 EC 43 BA DB
            A6 7A BD F3 20 C2 59 92 72 C5 DF E5 4C 0F 9D 75
            5B DB 71 DF FA 48 F0 E0 C6 46 2F 50 84 BD C8 6B
            25 81 59 FF EE A1 BD 92 2D 26 8C 5E 1B 95 06 4D
            F3 DB AD 89 D6 77 ED 12 C1 BD 65 3B BE B5 8A 03` 

**Second MPI**:

* length: `0x0005` = 5 bits (one byte)
* integer: `0x11` (`0x00010001`: 17)

## Private key material

See [Secret-Key Packet Formats](https://tools.ietf.org/html/rfc4880#section-5.5.3):

* One octet indicating string-to-key usage conventions: `0xFE` (`254`).
  255 or 254 indicates that a string-to-key specifier is being given.
* If string-to-key usage octet was 255 or 254, a one-octet symmetric encryption algorithm:
  `0x09` (`9`) => [AES with 256-bit key](https://tools.ietf.org/html/rfc4880#section-9.2).
* If string-to-key usage octet was 255 or 254, a [string-to-key specifier](https://tools.ietf.org/html/rfc4880#section-3.7).
  * Octet 0: `0x03` => [Iterated and Salted S2K](https://tools.ietf.org/html/rfc4880#section-3.7.1.3)
  * Octet 1: `0x08` => [SHA256](https://tools.ietf.org/html/rfc4880#section-9.4)
  * Octets 2-9: salt value is `9F 19 C8 66 F9 DF 00 F4` (see [Iterated and Salted S2K](https://tools.ietf.org/html/rfc4880#section-3.7.1.3)).
  * Octet 10: `0x60` (`96`) count, a one-octet, coded value (see [Iterated and Salted S2K](https://tools.ietf.org/html/rfc4880#section-3.7.1.3)). 

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

> Iterated-Salted S2K hashes the passphrase and salt data multiple
> times.  The total number of octets to be hashed is specified in the
> encoded count in the S2K specifier.  Note that the resulting count
> value is an octet count of how many octets will be hashed, not an
> iteration count.
  
See [Secret-Key Encryption](https://tools.ietf.org/html/rfc4880#section-3.7.2.1)
    
* If secret data is encrypted (string-to-key usage octet not zero),
  an Initial Vector (IV) of the same length as the cipher's block size
  (see [Secret-Key Packet Formats](https://tools.ietf.org/html/rfc4880#section-5.5.3)).
       
The cypher is [AES with 256-bit key](https://tools.ietf.org/html/rfc4880#section-9.2).
The block size is: 128 bits (see [wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)), 16 bytes.

Thus, the Initial Vector is: `70 EB 09 93 8C CF 0A BC FC 0F C9 60 C7 59 8E 46`.

* Plain or encrypted multiprecision integers comprising the secret key data.

> Algorithm-Specific Fields for RSA secret keys:
> * multiprecision integer (MPI) of RSA secret exponent d.
> * MPI of RSA secret prime value p.
> * MPI of RSA secret prime value q (p < q).
> * MPI of u, the multiplicative inverse of p, mod q.

The encrypted private key MPIs (encrypted with the 20-octet
SHA-1 hash of the plaintext of the algorithm-specific portion):

    1E 68 B2 A6 C8 9D 98 65 B5 52 27 7F 2B EB 27 8E
    A0 6D FA 17 1D 28 50 19 27 8A AC 33 AA 46 5B 31
    AE 2C 3E 31 A2 4F 0E 86 B3 4C 4E 9A 81 D3 43 BC
    B1 00 08 9A 98 F7 EE 47 12 6E B8 25 00 CE 87 7E
    84 E9 16 99 4F 00 7D 67 02 FB 10 8C B9 AE EF 55
    49 7E 47 34 1C 15 36 F2 B5 F3 D5 01 31 AE AB F9
    4B F1 8F 6C 6B 3B E5 8D 4D D3 3D ED 0A F9 71 BD
    9C 7F B6 1D 7E 46 0B 0D 93 A2 FE EB 6F 2F 88 5C
    A0 F6 F0 9A 83 F8 2B D7 AF BA C9 40 25 E3 60 5F
    9A 7F D6 1A B3 50 C4 C2 19 9A 4F 4F 74 92 53 9B
    02 3E 35 92 70 B0 0C F2 FD AD 70 24 67 00 00 42
    82 AF 3A 56 7E 50 D3 9E 26 25 03 42 5F 71 FE D8
    6B 58 DD 97 6E E9 06 01 FA 56 8B DE 37 E3 46 91
    E4 56 62 8B 7C B3 14 08 6C E5 26 ED D6 70 BD E7
    42 BC AF 30 1A 07 88 C3 86 36 6A B7 18 23 14 A8
    5D 83 E8 BD 85 0A 19 41 E3 EB 2A 85 16 0C F4 4D
    0D 4E 9C 7B 48 41 58 91 6C 5A 42 51 7D AA 2E 5C
    1F B0 71 32 06 96 DB A6 D5 2D 98 94 F1 69 64 5A
    DD 9D BC 6B 3E C8 CC 9F 1D EB 43 34 EA 11 CA 16
    71 E5 FA EB 33 EA 1B 0E 45 BF F8 0A 23 B4 61 08
    8D 31 4C 46 5F 31 29 E7 38 61 0A 48 D7 F1 12 30
    62 68 01 77 0C 08 A3 F5 AB D5 B9 11

The above block of bytes is encrypted. To get it, we selected the bytes knowing that:
* the total length of the packet is 516 bytes.
* the position of the last byte of the Initial Vector.

> **Please note**: If the string-to-key usage octet was
> 254, then a 20-octet SHA-1 hash of the plaintext of the
> algorithm-specific portion. **This checksum or hash is encrypted
> together with the algorithm-specific fields.**
> (see [Secret-Key Packet Formats](https://tools.ietf.org/html/rfc4880#section-5.5.3)) 
