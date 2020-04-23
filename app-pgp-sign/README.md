# Description

Illustrates the keyring management.

# Dependencies

* [Bouncy Castle PKIX, CMS, EAC, TSP, PKCS, OCSP, CMP, and CRMF APIs » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15to18/1.65)
* [Bouncy Castle OpenPGP API » 1.65](https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk15to18/1.65)

# Documentation

* [RFC 4880](https://tools.ietf.org/html/rfc4880)

# Technical notes

## Run the example

    java -cp "build/libs/app-pgp-sign-1.0-SNAPSHOT.jar:${PROJECT_ROOT_DIR}/lib/bcprov-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/bcpg-jdk15to18-1.65.jar:${PROJECT_ROOT_DIR}/lib/utils-1.0-SNAPSHOT.jar" com.beurive.Main

or

    java -cp "build\libs\app-pgp-sign-1.0-SNAPSHOT.jar;%PROJECT_ROOT_DIR%\lib\bcprov-jdk15to18-1.65.jar;%PROJECT_ROOT_DIR%\lib\bcpg-jdk15to18-1.65.jar;%PROJECT_ROOT_DIR%\lib\utils-1.0-SNAPSHOT.jar" com.beurive.Main

> Make sure to run `gradle setup` (at the project root level) first.

The program generates 4 files:

* `data/signature-master.pgp`
* `data/signature-subkey.pgp`
* `data/detached-signature-master.pgp`
* `data/detached-signature-subkey.pgp`

## GPG verifications

We will check that the generated signatures can be verified using GPG.

First, we need to look at the signatures in order to find out the ID of the key used to produce them.

    gpg --list-packets --verbose data/signature-master.pgp
    gpg --list-packets --verbose data/signature-subkey.pgp
    gpg --list-packets --verbose data/detached-signature-master.pgp
    gpg --list-packets --verbose data/detached-signature-subkey.pgp

The ID of the key master key is `6DB5AB4850BC5725`.
The ID of the sub key is `A1C01F10075E76FC`.

This ID should appear in the generated key rings.
Check that this is the case:

    gpg --list-packets --verbose data/secret-keyring.pgp

Then, we need to import this key into the GPG private and public key rings.
    
    gpg --import data/secret-keyring.pgp # (password: "password")
    gpg --import data/public-keyring.pgp

Once this is done, we must declare the master key into the GPG trust database. 

    gpg --edit-key 6DB5AB4850BC5725

Then, enter the command `trust` (see [this link](https://unix.stackexchange.com/questions/407062/gpg-list-keys-command-outputs-uid-unknown-after-importing-private-key-onto)).

OK. Now you can verify the signatures.
    
    gpg --verify data/signature-master.pgp

    gpg: Remarque : l'expéditeur a demandé « à votre seule attention »
    gpg: Signature faite le 04/23/20 18:18:59 Paris, Madrid (heure dÆÚtÚ)
    gpg:                avec la clef RSA 6DB5AB4850BC5725
    gpg:                issuer "denis@email.com"
    gpg: vérification de la base de confiance
    gpg: marginals needed: 3  completes needed: 1  trust model: pgp
    gpg: profondeur : 0  valables :   4  signées :   0
         confiance : 0 i., 0 n.d., 0 j., 0 m., 0 t., 4 u.
    gpg: Bonne signature de « denis@email.com » [ultime]


    gpg --verify data/signature-subkey.pgp

For the detached signature:
        
    gpg --verify data/detached-signature-master.pgp data/document-to-sign.txt

    gpg --verify data/detached-signature-subkey.pgp data/document-to-sign.txt



# Documentation

* [Signed Message](https://under-the-hood.sequoia-pgp.org/signed-message/)
* [Key structure](https://gnupg.org/faq/subkey-cross-certify.html)
* [Detached signature](https://subversivebytes.wordpress.com/2013/12/10/pgp-cryptography-with-the-legion-of-the-bouncy-castle-part-5/)
* [Signing Subkey Cross-Certification](https://gnupg.org/faq/subkey-cross-certify.html)
