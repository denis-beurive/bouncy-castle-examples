# (27) Key Flags subpacket

See [Key Flags](https://tools.ietf.org/html/rfc4880#section-5.2.3.21):

> This subpacket contains a list of binary flags that hold information
> about a key.  It is a string of octets, and an implementation MUST
> NOT assume a fixed size.  This is so it can grow over time.  If a
> list is shorter than an implementation expects, the unstated flags
> are considered to be zero.

| Hex  | Bin       | Meaning                                                                                |
|------|-----------|----------------------------------------------------------------------------------------|
| 0x01 | b00000001 | This key may be used to certify other keys.                                            |
| 0x02 | b00000010 | This key may be used to sign data.                                                     |
| 0x04 | b00000100 | This key may be used to encrypt communications.                                        |
| 0x08 | b00001000 | This key may be used to encrypt storage.                                               |
| 0x10 | b00010000 | The private component of this key may have been split by a secret-sharing mechanism.   |
| 0x20 | b00100000 | This key may be used for authentication.                                               |
| 0x80 | b10000000 | The private component of this key may be in the possession of more than one person.    |

If the flag value is `0x0C` = `b00001100`, then the key can be used to (`0x04` | `0x08` = `0x0C`):
* encrypt communications
* encrypt storage

When dumping a key using GPG, you can get information about the key usage, interpreted based on the key flags:

| Flag 	| character | Description                        |
|-------|-----------|------------------------------------|
| 0x01 	| `C`       | Key Certification                  |
| 0x02 	| `S` 	    | Sign Data                          |
| 0x04 	| `E` 	    | Encrypt Communications             |
| 0x08 	| `E` 	    | Encrypt Storage                    |
| 0x10 	|  	        | Split key                          |
| 0x20 	| `A` 	    | Authentication                     |
| 0x80 	|  	        | Held by more than one person       |

Example:

    gpg --list-keys D04E1857C36C89A1
    
    gpg: vérification de la base de confiance
    gpg: marginals needed: 3  completes needed: 1  trust model: pgp
    gpg: profondeur : 0  valables :  30  signées :   0
         confiance : 0 i., 0 n.d., 0 j., 0 m., 0 t., 30 u.
    pub   rsa2048 2020-06-01 [SC]
          F890D87039FFAFB622B4C9B03559C947CA49C02B
    uid          [  ultime ] Bertrand <bertrand@company.com>
    sub   rsa2048 2020-06-01 [E]

> Pay attention to the last line `sub   rsa2048 2020-06-01 [E]`.
> This line means that the subkey is an encryption key (`[E]`, like _encryption_).
