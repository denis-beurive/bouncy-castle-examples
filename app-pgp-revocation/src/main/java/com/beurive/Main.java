// This file shows how generate revocation certificates.

package com.beurive;

import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.beurive.pgp.Key;
import org.beurive.pgp.Keyring;
import org.beurive.pgp.Stream;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Main {

    /**
     * Add a Subkey Revocation Signature (type=0x28) - to a signing public subkey.
     *
     * Please note that the generated document is not a revocation certificate
     * for the subkey. It is only part of it. The revocation certificate for
     * the subkey includes all other information contained within the keyring that
     * holds the subkey.
     *
     * The added signature will have the following sub-packets:
     * * Reason for Revocation Sub Packet
     *   See https://tools.ietf.org/html/rfc4880#section-5.2.3.23
     * * Signature Creation Time Sub Packet
     *   See https://tools.ietf.org/html/rfc4880#section-5.2.3.4
     *
     * See https://tools.ietf.org/html/rfc4880#section-5.2.1
     *     https://tools.ietf.org/html/rfc4880#section-5.2.3.1
     *
     * Before (example):
     *
     * ┌────────────────────────────────────────────────────┐
     * │ Public Subkey Packet (tag=14)                      │
     * └────────────────────────────────────────────────────┘
     * ┌────────────────────────────────────────────────────┐
     * │ Subkey Binding Signature Packet (tag=2, type=0x18) │
     * └────────────────────────────────────────────────────┘
     *
     * After:
     *
     * ┌───────────────────────────────────────────────────────┐
     * │ Public Subkey Packet (tag=14)                         │
     * └───────────────────────────────────────────────────────┘
     * ┌───────────────────────────────────────────────────────┐
     * │ Subkey Binding Signature Packet (tag=2, type=0x18)    │
     * └───────────────────────────────────────────────────────┘
     * ┌───────────────────────────────────────────────────────┐
     * │ Subkey Revocation Signature Packet (tag=2, type=0x28) │
     * │ + Reason for Revocation                               │
     * │ + Signature Creation Time                             │
     * └───────────────────────────────────────────────────────┘
     *
     * @param inPublicSubkey The public (sub) key to certify.
     * @param inSigningPrivateKey The private key used to certify the public key.
     * Please note that this private key is the private key associated to the secret
     * @return The modified public key. The returned public key contains a Subkey
     * Revocation Signature.
     * @throws PGPException
     */

    static private PGPPublicKey addSubkeyRevocationSignature(PGPPublicKey inPublicSubkey,
                                                             PGPPrivateKey inSigningPrivateKey) throws PGPException {

        // Define subpackets.
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.setRevocationReason(false, RevocationReasonTags.KEY_COMPROMISED, "The computer holding the secret key is compromised!");
        subpacketGenerator.setSignatureCreationTime(false, new Date());

        // Create the signature generator.
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(
                        inPublicSubkey.getAlgorithm(),
                        HashAlgorithmTags.SHA1));
        signatureGenerator.init(PGPSignature.SUBKEY_REVOCATION, inSigningPrivateKey);
        signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());

        return PGPPublicKey.addCertification(inPublicSubkey, signatureGenerator.generate());
    }

    /**
     * Create a revocation certificate for a given subkey.
     *
     * This method binds a Subkey Revocation Signature Packet (tag=2, type=0x28)
     * to the subkey being revoked.
     *
     * See https://tools.ietf.org/html/rfc4880#section-5.2.1
     *
     * Before, we have a keyring that contains the subkey to revoke.
     * For example:
     *
     * ┌────────────────────────────────────────────────────┐
     * │ Public-Key Packet (tag=4)                          │
     * └────────────────────────────────────────────────────┘
     * ...
     * ┌────────────────────────────────────────────────────┐
     * │ Public Subkey Packet (tag=14)                      │
     * └────────────────────────────────────────────────────┘
     * ┌────────────────────────────────────────────────────┐
     * │ Subkey Binding Signature Packet (tag=2, type=0x18) │
     * └────────────────────────────────────────────────────┘
     *
     * Within the above keyring, we bind a Subkey Revocation
     * Signature Packet (tag=2, type=0x28) to the subkey to
     * revoke:
     *
     * ┌────────────────────────────────────────────────────┐
     * │ Public-Key Packet (tag=4)                          │
     * └────────────────────────────────────────────────────┘
     * ...
     * ┌────────────────────────────────────────────────────┐
     * │ Public Subkey Packet (tag=14)                      │
     * └────────────────────────────────────────────────────┘
     * ┌────────────────────────────────────────────────────┐
     * │ Subkey Binding Signature Packet (tag=2, type=0x18) │
     * └────────────────────────────────────────────────────┘
     * ┌───────────────────────────────────────────────────────┐
     * │ Subkey Revocation Signature Packet (tag=2, type=0x28) │
     * │ + Reason for Revocation                               │
     * │ + Signature Creation Time                             │
     * └───────────────────────────────────────────────────────┘
     *
     * @param inPublicKeyRing The public keyring that contains the subkey to revoke.
     * @param inSubKeyId The ID of the subkey to revoke.
     * @param inSigningPrivateKey The private key used to generate the Subkey Revocation
     * Signature Packet (tag=2, type=0x28) binded to the subkey.
     * @return The method returns the new public keyring that represents the revocation
     * certificate.
     * @throws Exception
     */

    private static PGPPublicKeyRing createRevocationCertificateForSubkey(PGPPublicKeyRing inPublicKeyRing,
                                                                         long inSubKeyId,
                                                                         PGPPrivateKey inSigningPrivateKey) throws Exception {

        // Add a Subkey Revocation Signature Packet (tag=2, type=0x28) to the subkey.
        PGPPublicKey subkey = inPublicKeyRing.getPublicKey(inSubKeyId);
        if (null == subkey) {
            throw new Exception(String.format("Unknown subkey which ID is %H!", inSubKeyId));
        }
        PGPPublicKey signedSubkey = addSubkeyRevocationSignature(subkey, inSigningPrivateKey);

        // Generate the certificate.
        // Note: if the given subkey (identified by its subkey) already exists in the
        // keyring, then it is replaced by its new version.
        return PGPPublicKeyRing.insertPublicKey(inPublicKeyRing, signedSubkey);
    }

    /**
     * Create a revocation certificate for a given master key.
     *
     * The generated document is a Key revocation signature Packet (tag=2, type=0x20).
     *
     * The returned signature contains the following sub packets:
     * * Reason for Revocation Sub Packet
     *   See https://tools.ietf.org/html/rfc4880#section-5.2.3.23
     * * Signature Creation Time Sub Packet
     *   See https://tools.ietf.org/html/rfc4880#section-5.2.3.4
     *
     * See https://tools.ietf.org/html/rfc4880#section-5.2.1
     *
     * ┌─────────────────────────────────────────────────────┐
     * │ Key Revocation Signature Packet  (tag=2, type=0x20) │
     * │ + Reason for Revocation                             │
     * │ + Signature Creation Time                           │
     * └─────────────────────────────────────────────────────┘
     *
     * @param inSecretKeyring The secret keyring that contains the master key to revoke.
     * @param inPassPhrase The passphrase that protects the master key.
     * @return The method returns the revocation certificate.
     * @throws PGPException
     */

    static private PGPSignature createRevocationCertificateForMasterKey(PGPSecretKeyRing inSecretKeyring,
                                                                        String inPassPhrase) throws PGPException {
        PGPPublicKey publicMasterKey = inSecretKeyring.getPublicKey();
        PGPSecretKey secretMasterKey = inSecretKeyring.getSecretKey();
        PGPPrivateKey privateMasterKey = secretMasterKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(inPassPhrase.toCharArray()));

        // Define subpackets.
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.setRevocationReason(false, RevocationReasonTags.KEY_COMPROMISED, "The computer holding the secret key is compromised!");
        subpacketGenerator.setSignatureCreationTime(false, new Date());

        // Create the signature generator.
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(
                        publicMasterKey.getAlgorithm(),
                        HashAlgorithmTags.SHA1));
        signatureGenerator.init(PGPSignature.KEY_REVOCATION, privateMasterKey);
        signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());
        return signatureGenerator.generateCertification(publicMasterKey);
    }


    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());
        String passPhrase = "password";
        String secretKeyRingPath = "data/secret-keyring.pgp";
        String publicKeyRingPath = "data/public-keyring.pgp";
        String subkeyWithRevocationSignaturePath = "data/subkey-with-revocation-signature.pgp";
        String subkeyRevocationCertificatePath = "data/subkey-revocation-certificate.pgp";
        String maskerKeyRevocationCertificatePath = "data/master-key-revocation-certificate.pgp";
        ArmoredOutputStream armoredOutputStream;
        BCPGOutputStream basicOut;

        try {
            // Load the secret keyring.
            PGPSecretKeyRing secretKeyRing = Keyring.loadSecretKeyring(secretKeyRingPath);
            PGPPublicKeyRing publicReyRing = Keyring.loadPublicKeyring(publicKeyRingPath);

            // Print the list of key IDs in the secret key ring.
            System.out.printf("List of key IDs in the key ring \"%s\":\n", secretKeyRingPath);
            PGPSecretKey[] keys = Keyring.getSecretKeys(Keyring.loadSecretKeyring(secretKeyRingPath), false);
            for (PGPSecretKey k: keys) {
                System.out.printf("\t- %016X (sign ? %s, master ? %s)\n",
                        k.getKeyID(),
                        k.isSigningKey() ? "yes" : "no",
                        k.isMasterKey() ? "yes" : "no");
            }

            // Get the required secret/private cryptographic documents.
            PGPSecretKey[] secretSigningKeys = Keyring.getSecretKeys(secretKeyRing, true);
            PGPSecretKey secretMasterKey = secretSigningKeys[0];
            PGPPrivateKey privateMasterKey = secretMasterKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase.toCharArray()));

            // Get the required public cryptographic documents.
            PGPPublicKey[] publicKeys = Keyring.getPublicKeys(publicReyRing);
            PGPPublicKey publicSubKey = publicKeys[1];

            // ---------------------------------------------------------------------------
            // Add a Subkey Revocation Signature Packet to a subkey.
            // ---------------------------------------------------------------------------

            System.out.printf("Add a Subkey Revocation Signature Packet to the subkey %X (which master key is %X) => %s\n",
                    publicSubKey.getKeyID(),
                    secretMasterKey.getKeyID(),
                    subkeyWithRevocationSignaturePath);
            PGPPublicKey certifiedPubKey = addSubkeyRevocationSignature(publicSubKey, privateMasterKey);
            Key.dumpPublicKey(certifiedPubKey, subkeyWithRevocationSignaturePath);

            // ---------------------------------------------------------------------------
            // Create a subkey revocation certificate.
            // ---------------------------------------------------------------------------

            System.out.printf("Create the revocation certificate for the subkey key %X => %s\n",
                    publicSubKey.getKeyID(),
                    subkeyRevocationCertificatePath);
            PGPPublicKeyRing skRevCertificate = createRevocationCertificateForSubkey(publicReyRing, publicSubKey.getKeyID(), privateMasterKey);

            // Write the certificate into a file.
            armoredOutputStream = Stream.getBufferedArmoredOutputStreamToFile(subkeyRevocationCertificatePath);
            basicOut = new BCPGOutputStream(armoredOutputStream);
            skRevCertificate.encode(basicOut);
            armoredOutputStream.close();

            // ---------------------------------------------------------------------------
            // Create the master key revocation certificate.
            // ---------------------------------------------------------------------------

            System.out.printf("Create the revocation certificate for the master key %X => %s\n",
                    secretMasterKey.getKeyID(),
                    maskerKeyRevocationCertificatePath);
            PGPSignature mkRevCertificate = createRevocationCertificateForMasterKey(secretKeyRing, passPhrase);

            // Write the certificate into a file.
            armoredOutputStream = Stream.getBufferedArmoredOutputStreamToFile(maskerKeyRevocationCertificatePath);
            basicOut = new BCPGOutputStream(armoredOutputStream);
            mkRevCertificate.encode(basicOut);
            armoredOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
