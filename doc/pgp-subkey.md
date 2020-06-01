# Note about subkeys

[Public-Subkey Packet (Tag 14)](https://tools.ietf.org/html/rfc4880#section-5.5.1.2): A Public-Subkey packet (tag 14)
has **exactly the same format** as a Public-Key packet, but denotes a subkey.

[Secret-Subkey Packet (Tag 7)](https://tools.ietf.org/html/rfc4880#section-5.5.1.4): A Secret-Subkey packet (tag 7) is
the subkey analog of the Secret Key packet and has **exactly the same format**.

In other words, through a structural analyze, the only thing that differentiates a subkey from a key is the tag's value:

|        | Public | Secret |
|--------|--------|--------|
| key    | 6      | 5      |
| subkey | 14     | 7      |
