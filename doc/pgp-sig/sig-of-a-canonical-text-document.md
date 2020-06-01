# 0x01: Signature of a canonical text document

> This means the signer owns it, created it, or certifies that it
> has not been modified.  The signature is calculated over the text
> data with its line endings converted to <CR><LF>.

Choose a key that will be used to sign a document:

    gpg --list-keys

Let say that we choose the key identified by its bound user’s email address `bob@company.com`.

We sign the document:

    gpg --sign --textmode --default-key bob@company.com file.txt
    
> Please note the use of the option [--default-key](https://gnupg.org/documentation/manpage.html).
    
Let inspect the generated signature:

    gpg --list-packet 

Let inspect the generated signature:

    gpg --list-packet file.txt.gpg
    
    # off=0 ctb=a3 tag=8 hlen=1 plen=0 indeterminate
    :compressed packet: algo=1
    # off=2 ctb=90 tag=4 hlen=2 plen=13
    :onepass_sig packet: keyid B1589F0D0EA747F5
            version 3, sigclass 0x01, digest 8, pubkey 1, last=1
    # off=17 ctb=cb tag=11 hlen=2 plen=20 new-ctb
    :literal data packet:
            mode t (74), created 1591016892, name="file.txt",
            raw data: 6 bytes
    # off=39 ctb=89 tag=2 hlen=3 plen=324
    :signature packet: algo 1, keyid B1589F0D0EA747F5
            version 4, created 1591016892, md5len 0, sigclass 0x01
            digest algo 8, begin of digest 53 55
            hashed subpkt 33 len 21 (issuer fpr v4 BF639C0FD3CD3872828856C3B1589F0D0EA747F5)
            hashed subpkt 2 len 4 (sig created 2020-06-01)
            hashed subpkt 28 len 15 (signer's user ID)
            subpkt 16 len 8 (issuer key ID B1589F0D0EA747F5)
            data: [2045 bits]
            
We can see that GPG create a _Signature of a canonical text document_ (`sigclass 0x01`).
