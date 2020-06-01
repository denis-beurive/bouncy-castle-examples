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

However, from a _functional_ point of view, keys and subkeys present one fundamental difference:

> See[Key Structures](https://tools.ietf.org/html/rfc4880#section-12.1) In a V4 key, **the primary key MUST
> be a key capable of certification**. The subkeys may be keys of any **other type**.

Thus, we have:

| Type of key | Certification | Signing | Encryption | Authentication |
|-------------|---------------|---------|------------|----------------|
| primary key | x             | x       | x          | x              |
| subkey      |               | x       | x          | x              |

Please note that you can use GPG to show the potential usage of (sub)keys:

    gpg --list-secret-keys --keyid-format LONG

With (see [this link](https://unix.stackexchange.com/questions/31996/how-are-the-gpg-usage-flags-defined-in-the-key-details-listing)):

| Meaning             | Code |
|---------------------|------|
| `PUBKEY_USAGE_SIG`  | S    |
| `PUBKEY_USAGE_CERT` | C    |
| `PUBKEY_USAGE_ENC`  | E    |
| `PUBKEY_USAGE_AUTH` | A    |
