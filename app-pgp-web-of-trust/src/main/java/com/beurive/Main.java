// This example illustrates the creation of keys and key rings.

package com.beurive;

import java.util.Date;
import java.security.Security;
import java.util.Iterator;

import org.beurive.pgp.Key;
import org.beurive.pgp.Keyring;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;


public class Main {

    /**
     * Add a Positive Certification Signature (tag=2, type=0x13) to a given public key.
     * @param inPublicSubkey The public key.
     * @param inSigningPrivateKey The private key used to generate the signature.
     * This should be the private key associated to the master key.
     * @return The method returns the signed public key.
     * @throws PGPException
     */

    static public PGPPublicKey addPositiveCertificationSignature(PGPPublicKey inPublicSubkey,
                                                                 PGPPrivateKey inSigningPrivateKey) throws PGPException {

        // Define subpackets.
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.setSignatureCreationTime(false, new Date());

        // Create the signature generator.
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(
                        inPublicSubkey.getAlgorithm(),
                        HashAlgorithmTags.SHA1));
        signatureGenerator.init(PGPSignature.POSITIVE_CERTIFICATION, inSigningPrivateKey);
        signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());

        return PGPPublicKey.addCertification(inPublicSubkey, signatureGenerator.generate());
    }

    /**
     * Verify that a public key (the certified key) is certified by another public key
     * (the certifier key).
     * @param inCertifiedPublicKey The certified key.
     * @param inCertifierPublicKey The certifier key.
     * @return If the certified key is certified by the certifier key, then the method returns the value true.
     * Otherwise, the method returns the value false.
     * @warning We don't check that the so-called certified key contains a certification signature.
     * @throws PGPException
     */

    public static boolean verifyCertification(PGPPublicKey inCertifiedPublicKey,
                                              PGPPublicKey inCertifierPublicKey) throws PGPException {
        Iterator<PGPSignature> it = inCertifiedPublicKey.getKeySignatures();
        while (it.hasNext()) {
            PGPSignature sig = it.next();
            if (sig.isCertification()) {
                sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), inCertifierPublicKey);
                if (sig.verify()) return true;
            }
        }
        return false;
    }

    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());
        final String passPhrase = "password";
        final String bobSecKeyRingPath = "data/sec-bob.key";
        final String aliceSecKeyRingPath = "data/sec-alice.key";
        final String bobPubKeyRingPath = "data/pub-bob.key";
        final String alicePubKeyRingPath = "data/pub-alice.key";
        final String bobNewPubKeyRingPath = "data/new-pub-bob.key";
        final String aliceNewPubKeyRingPath = "data/new-pub-alice.key";

        try {
            System.out.printf("Load Bob secret keyring \"%s\"\n", bobSecKeyRingPath);
            PGPSecretKeyRing bobSecKeyRing = Keyring.loadSecretKeyring(bobSecKeyRingPath);
            PGPSecretKey bobSecMasterKey = bobSecKeyRing.getSecretKey();
            PGPPrivateKey bobPrivMasterKey = Key.extractPrivateKey(bobSecMasterKey, passPhrase.toCharArray());
            System.out.printf("%s", Keyring.dumpSecret(bobSecKeyRing, "  ").toString());

            System.out.printf("Load Bob public keyring \"%s\"\n", bobPubKeyRingPath);
            PGPPublicKeyRing bobPubKeyRing = Keyring.loadPublicKeyring(bobPubKeyRingPath);
            PGPPublicKey bobPubMasterKey = bobPubKeyRing.getPublicKey();
            System.out.printf("%s", Keyring.dumpPublic(bobPubKeyRing, "  ").toString());

            System.out.printf("Load Alice secret keyring \"%s\"\n", aliceSecKeyRingPath);
            PGPSecretKeyRing aliceSecKeyRing  = Keyring.loadSecretKeyring(aliceSecKeyRingPath);
            PGPSecretKey aliceSecMasterKey = aliceSecKeyRing.getSecretKey();
            PGPPrivateKey alicePrivMasterKey = Key.extractPrivateKey(aliceSecMasterKey, passPhrase.toCharArray());
            System.out.printf("%s", Keyring.dumpSecret(aliceSecKeyRing, "  ").toString());

            System.out.printf("Load Alice public keyring \"%s\"\n", alicePubKeyRingPath);
            PGPPublicKeyRing alicePubKeyRing = Keyring.loadPublicKeyring(alicePubKeyRingPath);
            PGPPublicKey alicePubMasterKey = alicePubKeyRing.getPublicKey();
            System.out.printf("%s", Keyring.dumpPublic(alicePubKeyRing, "  ").toString());

            System.out.printf("Bob signs Alice's key\n");
            PGPPublicKey signedAliceKey = addPositiveCertificationSignature(alicePubMasterKey, bobPrivMasterKey);
            System.out.printf("Alice signs Bob's key\n");
            PGPPublicKey signedBobKey = addPositiveCertificationSignature(bobPubMasterKey, alicePrivMasterKey);

            alicePubKeyRing = PGPPublicKeyRing.insertPublicKey(alicePubKeyRing, signedAliceKey);
            bobPubKeyRing = PGPPublicKeyRing.insertPublicKey(bobPubKeyRing, signedBobKey);

            System.out.printf(String.format("Dump the new Alice public keyring into \"%s\"\n", aliceNewPubKeyRingPath));
            System.out.printf(String.format("> gpg --list-packet %s\n", aliceNewPubKeyRingPath));
            Keyring.dumpPublicToPath(alicePubKeyRing, aliceNewPubKeyRingPath);
            System.out.printf(String.format("Dump the new Bob public keyring into \"%s\"\n", bobNewPubKeyRingPath));
            System.out.printf(String.format("> gpg --list-packet %s\n", bobNewPubKeyRingPath));
            Keyring.dumpPublicToPath(bobPubKeyRing, bobNewPubKeyRingPath);

            // Verify the certifications.
            PGPPublicKey certifiedKey;
            PGPPublicKey certifierKey;

            certifiedKey = alicePubKeyRing.getPublicKey();
            certifierKey = bobPubKeyRing.getPublicKey();
            if (verifyCertification(certifiedKey, certifierKey)) {
                System.out.printf("%X is certified by %X\n", certifiedKey.getKeyID(), certifierKey.getKeyID());
            }

            certifiedKey = bobPubKeyRing.getPublicKey();
            certifierKey = alicePubKeyRing.getPublicKey();
            if (verifyCertification(certifiedKey, certifierKey)) {
                System.out.printf("%X is certified by %X\n", certifiedKey.getKeyID(), certifierKey.getKeyID());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
