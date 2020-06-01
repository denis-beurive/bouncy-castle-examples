# 0x00: Signature of a binary document

> This means the signer owns it, created it, or certifies that it
> has not been modified.

Choose a key that will be used to sign a document:

    gpg --list-keys

Let say that we choose the key identified by its bound user’s email address `bob@company.com`.

We sign the document:

    gpg --sign --default-key bob@company.com file.pdf
    
Let inspect the generated signature:

    gpg --list-packet file.pdf
    
    # off=0 ctb=a3 tag=8 hlen=1 plen=0 indeterminate
    :compressed packet: algo=1
    # off=2 ctb=90 tag=4 hlen=2 plen=13
    :onepass_sig packet: keyid B1589F0D0EA747F5
            version 3, sigclass 0x00, digest 8, pubkey 1, last=1
    # off=17 ctb=ae tag=11 hlen=5 plen=2097170
    :literal data packet:
            mode b (62), created 1591016225, name="file.pdf",
            raw data: 2097156 bytes
    # off=2097192 ctb=89 tag=2 hlen=3 plen=324
    :signature packet: algo 1, keyid B1589F0D0EA747F5
            version 4, created 1591016225, md5len 0, sigclass 0x00
            digest algo 8, begin of digest 5b 1b
            hashed subpkt 33 len 21 (issuer fpr v4 BF639C0FD3CD3872828856C3B1589F0D0EA747F5)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 28 len 15 (signer's user ID)
            subpkt 16 len 8 (issuer key ID B1589F0D0EA747F5)
            data: [2047 bits] 

We can see that GPG create a _Signature of a binary document_ (`sigclass 0x00`).
