# Anatomy of a master key revocation certificate

Let's see what, precisely, is a key revocation certificate.

We will use PGP to generate a key (that is a master key and a subkey).
And, then, we will look at the generated revocation certificate. 


First, create a key. Execute the following command:

    gpg --full-generate-key

Here is the full output:

    gpg (GnuPG) 2.2.19; Copyright (C) 2019 Free Software Foundation, Inc.
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.

    Sélectionnez le type de clef désiré :
       (1) RSA et RSA (par défaut)
       (2) DSA et Elgamal
       (3) DSA (signature seule)
       (4) RSA (signature seule)
      (14) Existing key from card
    Quel est votre choix ? 1
    les clefs RSA peuvent faire une taille comprise entre 1024 et 4096 bits.
    Quelle taille de clef désirez-vous ? (2048)
    La taille demandée est 2048 bits
    Veuillez indiquer le temps pendant lequel cette clef devrait être valable.
             0 = la clef n'expire pas
          <n>  = la clef expire dans n jours
          <n>w = la clef expire dans n semaines
          <n>m = la clef expire dans n mois
          <n>y = la clef expire dans n ans
    Pendant combien de temps la clef est-elle valable ? (0)
    La clef n'expire pas du tout
    Est-ce correct ? (o/N) o

    GnuPG doit construire une identité pour identifier la clef.

    Nom réel : Denis BEURIVE
    Adresse électronique : denis@test1.org
    Commentaire :
    Vous avez sélectionné cette identité :
        « Denis BEURIVE <denis@test1.org> »

    Changer le (N)om, le (C)ommentaire, l'(A)dresse électronique
    ou (O)ui/(Q)uitter ? O
    De nombreux octets aléatoires doivent être générés. Vous devriez faire
    autre chose (taper au clavier, déplacer la souris, utiliser les disques)
    pendant la génération de nombres premiers ; cela donne au générateur de
    nombres aléatoires une meilleure chance d'obtenir suffisamment d'entropie.
    gpg: AllowSetForegroundWindow(3488) failed: AccÞs refusÚ.

    gpg: AllowSetForegroundWindow(7868) failed: AccÞs refusÚ.

    De nombreux octets aléatoires doivent être générés. Vous devriez faire
    autre chose (taper au clavier, déplacer la souris, utiliser les disques)
    pendant la génération de nombres premiers ; cela donne au générateur de
    nombres aléatoires une meilleure chance d'obtenir suffisamment d'entropie.
    gpg: clef 2F3DC8F2A29E5F10 marquée de confiance ultime.
    gpg: revocation certificate stored as 'C:/Users/denis.beurive/AppData/Roaming/gnupg/openpgp-revocs.d\ADA313C0C49DDD87B075E9802F3DC8F2A29E5F10.rev'
    les clefs publique et secrète ont été créées et signées.

    pub   rsa2048 2020-05-21 [SC]
          ADA313C0C49DDD87B075E9802F3DC8F2A29E5F10
    uid                      Denis BEURIVE <denis@test1.org>
    sub   rsa2048 2020-05-21 [E]

Please, pay attention to this line:

    gpg: revocation certificate stored as 'C:/Users/denis.beurive/AppData/Roaming/gnupg/openpgp-revocs.d\ADA313C0C49DDD87B075E9802F3DC8F2A29E5F10.rev'

OK. Thus, we have a revocation certificate! Let's see what's inside:

    Ceci est un certificat de révocation pour la clef OpenPGP :

    pub   rsa2048 2020-05-21 [S]
          ADA313C0C49DDD87B075E9802F3DC8F2A29E5F10
    uid          Denis BEURIVE <denis@test1.org>

    A revocation certificate is a kind of "kill switch" to publicly
    declare that a key shall not anymore be used.  It is not possible
    to retract such a revocation certificate once it has been published.

    Use it to revoke this key in case of a compromise or loss of
    the secret key.  However, if the secret key is still accessible,
    it is better to generate a new revocation certificate and give
    a reason for the revocation.  For details see the description of
    of the gpg command "--generate-revocation" in the GnuPG manual.

    To avoid an accidental use of this file, a colon has been inserted
    before the 5 dashes below.  Remove this colon with a text editor
    before importing and publishing this revocation certificate.

    :-----BEGIN PGP PUBLIC KEY BLOCK-----
    Comment: This is a revocation certificate

    iQE2BCABCAAgFiEEraMTwMSd3YewdemALz3I8qKeXxAFAl7GgXUCHQAACgkQLz3I
    8qKeXxBDmAf/Q7Mij3dIwkje9+EJFtECJrLMbdc+BD+M0Nej0EBNv6ZLooEAWDl8
    Wxf+fdug+U7WHsSKi9ODDTqhcmOx35tt0X+H2AuCfteTayVi5btGJxp89xuzCvlv
    th3xpkNSqo2lqlsifcmLWTIVSNoXorl5xBYIkjR3w7nOjvpNP7YNGFZJ3JR1//lr
    X/wxpjD4psQoFSDTrbmwk45qugiRqHS8NcK83u5xKIMgn8cPd8izGcJeqJfctgBD
    zRTzmqTX/yorgKhEILrM9Ci81meAss9If9NPjdxlEH+m9F5TYRR5s++THoUiGdeC
    r03o0uGxU323A/7+ONidWuhSJKJjEBTwrg==
    =ktKN
    -----END PGP PUBLIC KEY BLOCK-----

This file contains two parts:
* the first part is made of a text, which presents the purpose of the file.
* the second part is the PGP document that represents the revocation certificate.

Let's copy the second part of the file into a new file that we call "revocation-cert.pgp".
The content of the file is:

    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Comment: This is a revocation certificate

    iQE2BCABCAAgFiEEraMTwMSd3YewdemALz3I8qKeXxAFAl7GgXUCHQAACgkQLz3I
    8qKeXxBDmAf/Q7Mij3dIwkje9+EJFtECJrLMbdc+BD+M0Nej0EBNv6ZLooEAWDl8
    Wxf+fdug+U7WHsSKi9ODDTqhcmOx35tt0X+H2AuCfteTayVi5btGJxp89xuzCvlv
    th3xpkNSqo2lqlsifcmLWTIVSNoXorl5xBYIkjR3w7nOjvpNP7YNGFZJ3JR1//lr
    X/wxpjD4psQoFSDTrbmwk45qugiRqHS8NcK83u5xKIMgn8cPd8izGcJeqJfctgBD
    zRTzmqTX/yorgKhEILrM9Ci81meAss9If9NPjdxlEH+m9F5TYRR5s++THoUiGdeC
    r03o0uGxU323A/7+ONidWuhSJKJjEBTwrg==
    =ktKN
    -----END PGP PUBLIC KEY BLOCK-----
    
Then, let's dump the structure of the document:

    gpg --list-packet revocation-cert.pgp
    
The result is:

    # off=0 ctb=89 tag=2 hlen=3 plen=310
    :signature packet: algo 1, keyid 2F3DC8F2A29E5F10
            version 4, created 1590067573, md5len 0, sigclass 0x20
            digest algo 8, begin of digest 43 98
            hashed subpkt 33 len 21 (issuer fpr v4 ADA313C0C49DDD87B075E9802F3DC8F2A29E5F10)
            hashed subpkt 2 len 4 (sig created 2020-05-21)
            hashed subpkt 29 len 1 (revocation reason 0x00 ())
            subpkt 16 len 8 (issuer key ID 2F3DC8F2A29E5F10)
            data: [2047 bits]

Conclusion: a revocation certification is made of a single [Key Revocation Signature](https://tools.ietf.org/html/rfc4880#section-5.2.1) packet (`sigclass 0x20`).

> Please note that you can generate a revocation certificate directly:
>
> `gpg -o revocation-cert.pgp --gen-revoke ADA313C0C49DDD87B075E9802F3DC8F2A29E5F10`
