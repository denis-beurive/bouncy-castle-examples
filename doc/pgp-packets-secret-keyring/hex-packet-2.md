# Second packet

`0xB4`: `0b10110100`

* [format](https://tools.ietf.org/html/rfc4880#section-4.2.1): old
* [tag](https://tools.ietf.org/html/rfc4880#section-4.3): `0b1101` = `13` => User ID Packet
* [type](https://tools.ietf.org/html/rfc4880#section-4.2.1): `0b00` = `0` => The packet has a one-octet length.
  The header is 2 octets long.  
* length = `0x0F` = 15 bytes.

body:

    6F 77 6E 65 72 40 65 6D 61 69 6C 2E 63 6F 6D
