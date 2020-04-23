// This example illustrates the creation of keys and key rings.

package com.beurive;

import java.lang.IllegalArgumentException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Date;
import java.io.IOException;
import java.security.Security;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.util.Iterator;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class Main {

    /**
     * Create a ArmoredOutputStream to a file.
     * @param inPath Path to the file.
     * @return a new ArmoredOutputStream.
     * @throws IOException
     */

    private static ArmoredOutputStream getArmoredOutputStream(String inPath) throws IOException {
        return new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(new File(inPath))));
    }

    /**
     * Create a BCPGOutputStream to a file.
     * @param inPath Path to the file.
     * @return a new BCPGOutputStream.
     * @throws IOException
     */

    private static BCPGOutputStream getBCPGOutputStream(String inPath) throws IOException {
        return new BCPGOutputStream(new BufferedOutputStream(new FileOutputStream(new File(inPath))));
    }

    /**
     * Dump a given keyring into a file identified by its path.
     * @param inKeyRing The keyring to dump.
     * @param inPath Path to the target file.
     * @throws IOException
     */

    private static void dumpKeyRing(PGPKeyRing inKeyRing, String inPath) throws IOException {
        ArmoredOutputStream outputStream = getArmoredOutputStream(inPath);
        inKeyRing.encode(outputStream);
        outputStream.close();
    }

    /**
     * Extract the private key from a given secret key.
     * @param pgpSecKey The secret key.
     * @param passPhrase The private ket pass phrase.
     * @return The private key.
     * @throws PGPException
     */

    private static PGPPrivateKey extractPrivateKey(PGPSecretKey pgpSecKey, char[] passPhrase)
            throws PGPException {
        PGPPrivateKey privateKey = null;
        BcPGPDigestCalculatorProvider calculatorProvider = new BcPGPDigestCalculatorProvider();
        BcPBESecretKeyDecryptorBuilder secretKeyDecryptorBuilder = new BcPBESecretKeyDecryptorBuilder(calculatorProvider);
        PBESecretKeyDecryptor pBESecretKeyDecryptor = secretKeyDecryptorBuilder.build(passPhrase);

        try {
            privateKey = pgpSecKey.extractPrivateKey(pBESecretKeyDecryptor);
        } catch (PGPException e) {
            throw new PGPException("invalid privateKey passPhrase: " + String.valueOf(passPhrase), e);
        }

        return privateKey;
    }

    /**
     * Dump a given public key into a file identified by its path.
     * @param inPublicKey The public key to dump.
     * @param inPath Path to the target file.
     * @throws IOException
     */

    private static void dumpPublicKey(PGPPublicKey inPublicKey, String inPath) throws IOException {
        ArmoredOutputStream outputStream = getArmoredOutputStream(inPath);
        inPublicKey.encode(outputStream);
        outputStream.close();
    }

    /**
     * Dump a given secret key into 2 files:
     * - one file that represents the PGP secret key.
     * - one file that contains the mathematical components of the key.
     *   The content of this file depends on the type of key (RSA, DSA or El Gamal).
     * @param inSecreteKey The secret key to dump.
     * @param inPathPrefix Path to the target file.
     * @param inPassPhrase The passphrase for the private key.
     * @throws IOException
     * @throws PGPException
     */

    private static void dumpSecretKey(PGPSecretKey inSecreteKey,
                                      String inPathPrefix,
                                      char[] inPassPhrase) throws IOException, PGPException {
        ArmoredOutputStream outputSecretKeyStream = getArmoredOutputStream(inPathPrefix + ".pgp");
        inSecreteKey.encode(outputSecretKeyStream);
        outputSecretKeyStream.close();

        PGPPrivateKey privateKey = extractPrivateKey(inSecreteKey, inPassPhrase);
        BCPGKey packet = privateKey.getPrivateKeyDataPacket();

        if (packet instanceof org.bouncycastle.bcpg.RSASecretBCPGKey) {
            // @see org.bouncycastle.bcpg.RSASecretBCPGKey.encode
            // This will dump 4 MPIs.
            BCPGOutputStream outputStream = getBCPGOutputStream(inPathPrefix + "-private-rsa.data");
            org.bouncycastle.bcpg.RSASecretBCPGKey key = (org.bouncycastle.bcpg.RSASecretBCPGKey)packet;
            key.encode(outputStream);
            outputStream.close();
        }

        if (packet instanceof org.bouncycastle.bcpg.DSASecretBCPGKey) {
            // @see org.bouncycastle.bcpg.DSASecretBCPGKey.encode
            // This will dump 1 MPI.
            BCPGOutputStream outputStream = getBCPGOutputStream(inPathPrefix + "-private-dsa.data");
            org.bouncycastle.bcpg.DSASecretBCPGKey key = (org.bouncycastle.bcpg.DSASecretBCPGKey)packet;
            key.encode(outputStream);
            outputStream.close();
        }

        if (packet instanceof org.bouncycastle.bcpg.ElGamalSecretBCPGKey) {
            // @see org.bouncycastle.bcpg.ElGamalSecretBCPGKey.encode
            // This will dump 1 MPI.
            BCPGOutputStream outputStream = getBCPGOutputStream(inPathPrefix + "-private-elgamal.data");
            org.bouncycastle.bcpg.ElGamalSecretBCPGKey key = (org.bouncycastle.bcpg.ElGamalSecretBCPGKey)packet;
            key.encode(outputStream);
            outputStream.close();
        }
    }

    /**
     * Dump all (public) keys within a given public keyring.
     * @param inKeyRing The public keyring to dump.
     * @param inPathPrefix The path prefix of the target file.
     * @throws IOException
     */

    private static void dumpAllPublicKeys(PGPPublicKeyRing inKeyRing,
                                          String inPathPrefix) throws IOException {
        Iterator<PGPPublicKey> keyIterator = inKeyRing.iterator();
        int id = 1;
        while (true) {
            if (! keyIterator.hasNext()) break;
            dumpPublicKey(keyIterator.next(), inPathPrefix + id++ + ".pgp");
        }
    }

    /**
     * Dump all (secret) keys within a given secret keyring.
     * @param inKeyRing The secret keyring to dump.
     * @param inPathPrefix The path prefix of the target file.
     * @param inPassPhrase The passphrase for the private keys.
     * @throws IOException
     */

    private static void dumpAllSecretKeys(PGPSecretKeyRing inKeyRing,
                                          String inPathPrefix,
                                          String inPassPhrase) throws IOException, PGPException {
        Iterator<PGPSecretKey> keyIterator = inKeyRing.iterator();
        char[] passPhrase = inPassPhrase.toCharArray();
        int id = 1;
        while (true) {
            if (! keyIterator.hasNext()) break;
            PGPSecretKey key = keyIterator.next();
            dumpSecretKey(key, inPathPrefix + id++, passPhrase);
        }
    }

    /**
     * Create a RSA key pair.
     * @return An RSA key pair.
     * @throws PGPException
     */

    private static PGPKeyPair createRsaKeyPair() throws PGPException {
        // Create a key pair generator for RSA.
        RSAKeyPairGenerator rsaKpg = new RSAKeyPairGenerator();
        BigInteger publicExponent = BigInteger.valueOf(0x11);
        SecureRandom random = new SecureRandom();
        int strength = 512;
        int certainty = 25;
        rsaKpg.init(new RSAKeyGenerationParameters(
                publicExponent,
                random,
                strength,
                certainty));

        // Generate the RSA keys.
        AsymmetricCipherKeyPair rsaKp = rsaKpg.generateKeyPair();
        return new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKp, new Date());
    }

    /**
     * Create a DSA PGP key pair.
     * @return A DSA key pair.
     * @throws PGPException
     */

    private static PGPKeyPair createDsaKeyPair() throws PGPException {
        DSAParametersGenerator dsaPGen = new DSAParametersGenerator();
        int size = 512;
        int certainty = 10;
        dsaPGen.init(size, certainty, new SecureRandom());
        DSAKeyPairGenerator dsaKpg = new DSAKeyPairGenerator();
        dsaKpg.init(new DSAKeyGenerationParameters(new SecureRandom(), dsaPGen.generateParameters()));
        AsymmetricCipherKeyPair  dsaKp = dsaKpg.generateKeyPair();
        return new BcPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
    }

    /**
     * Create an El Gamal key pair
     * @return An El Gamal key pair
     * @throws PGPException
     */

    private static PGPKeyPair createElGamalKeyPair() throws PGPException {
        ElGamalKeyPairGenerator elgKpg = new ElGamalKeyPairGenerator();
        BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
        ElGamalParameters elParams = new ElGamalParameters(p, g);
        elgKpg.init(new ElGamalKeyGenerationParameters(new SecureRandom(), elParams));
        AsymmetricCipherKeyPair elgKp = elgKpg.generateKeyPair();
        return new BcPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
    }

    /**
     * Return a keyring generator.
     *
     * @param inPairs List of PGP key pairs.
     * @param inIdentity Identity of the key owner.
     * @param inPassPhrase Passphrase used to encrypt the secret keys.
     * @return A new keyring generator.
     * @throws IllegalArgumentException
     * @throws PGPException
     */

    private static PGPKeyRingGenerator getKeyRingGenerator(PGPKeyPair[] inPairs,
                                                           String inIdentity,
                                                           String inPassPhrase) throws IllegalArgumentException, PGPException {
        if (0 == inPairs.length) {
            throw new IllegalArgumentException("No key given!");
        }
        char[] passPhrase = inPassPhrase.toCharArray();

        // See RFC 4840: [9.4. Hash Algorithms]
        // https://tools.ietf.org/html/rfc4880#section-9.4
        // Note: only SHA1 supported for key checksum calculations
        // org.bouncycastle.openpgp.PGPException: only SHA1 supported for key checksum calculations.
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                // See RFC 4880: [5.2.1. Signature Types]
                // https://tools.ietf.org/html/rfc4880#section-5.2.1
                // PGPSignature.POSITIVE_CERTIFICATION,
                PGPSignature.DEFAULT_CERTIFICATION, // 0x10
                inPairs[0],
                inIdentity,
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(inPairs[0].getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase)
        );

        for (int i=1; i<inPairs.length; i++) {
            keyRingGen.addSubKey(inPairs[i]);
        }
        return keyRingGen;
    }

    /**
     * See https://gnupg.org/faq/subkey-cross-certify.html
     * Recall that subkeys are signed by the primary key to show they belong to the primary key.
     * However, the signing subkey does not sign the primary to show that it is owned by the primary.
     * This allows an attacker to take a signing subkey and attach it to their own key.
     * @param inSigningSecretSubKey
     * @param inMasterPublicKeyToBeSigned
     * @param inPassPhrase
     * @throws PGPException
     */

    private static PGPPublicKey backSign(PGPSecretKey inSigningSecretSubKey,
                                 PGPPublicKey inMasterPublicKeyToBeSigned,
                                 String inPassPhrase) throws PGPException {

        // Get the private key of the sub key (that will be used to sign the master key).
        PGPPrivateKey privateKey = extractPrivateKey(inSigningSecretSubKey, inPassPhrase.toCharArray());
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(inSigningSecretSubKey.getPublicKey()
                        .getAlgorithm(), PGPUtil.SHA256));
        signatureGenerator.init(PGPSignature.DIRECT_KEY, privateKey);

        // Set the user IDs.
        Iterator<String> it = inSigningSecretSubKey.getPublicKey().getUserIDs();
        while (it.hasNext()) {
            String userId = it.next();
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            // If you look at the code of the method "setSignerUserID()", then you see that this method can be called more than once:
            //    list.add(new SignerUserID(isCritical, userID));
            // This, it is possible to set more than one user ID.
            spGen.setSignerUserID(false, userId);
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }

        PGPSignature signature = signatureGenerator.generateCertification(inMasterPublicKeyToBeSigned);
        return PGPPublicKey.addCertification(inMasterPublicKeyToBeSigned, signature);
    }

    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());
        String passPhrase = "password";

        try {
            // -------------------------------------------------------
            // Create a key ring with 3 key pairs.
            // -------------------------------------------------------

            PGPKeyPair RsaKeyPair = createRsaKeyPair();
            PGPKeyPair DsaKeyPair = createDsaKeyPair();
            PGPKeyPair ElGamalKeyPair = createElGamalKeyPair();

            // Create the keyring generator.
            // The master key is the first of the list, that is: RsaKeyPair.
            PGPKeyPair[] keyPairs1 = {RsaKeyPair, DsaKeyPair, ElGamalKeyPair};
            PGPKeyRingGenerator keyRingGen = getKeyRingGenerator(keyPairs1,
                    "denis@email.com",
                    passPhrase);

            // Generate the PGP keys.
            PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
            PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

            // Cross signing
//            Iterator<PGPSecretKey> it = secRing.getSecretKeys();
//            while (it.hasNext()) {
//                PGPSecretKey secKey = it.next();
//                if (! secKey.isSigningKey()) continue;
//                if (secKey.isMasterKey()) continue;
//                System.out.printf("Cross sign master PUB [%H] with sub SEC [%H]",
//                        pubRing.getPublicKey().getKeyID(),
//                        secKey.getKeyID());
//                backSign(secKey, pubRing.getPublicKey(secKey.getKeyID()), passPhrase);
//            }

            // Dump everything.
            dumpKeyRing(pubRing, "public-keyring.pgp");
            dumpKeyRing(secRing, "secret-keyring.pgp");
            dumpAllPublicKeys(pubRing, "public-key-");
            dumpAllSecretKeys(secRing, "secret-key-", passPhrase);

            // -------------------------------------------------------
            // Create a key ring with 1 key pair.
            // -------------------------------------------------------

            // Create the keyring generator.
            PGPKeyPair[] keyPairs2 = {RsaKeyPair};
            keyRingGen = getKeyRingGenerator(keyPairs1,
                    "denis@email.com",
                    passPhrase);

            // Generate the PGP keys.
            pubRing = keyRingGen.generatePublicKeyRing();
            secRing = keyRingGen.generateSecretKeyRing();

            // Dump everything.
            dumpKeyRing(pubRing, "single-public-keyring.pgp");
            dumpKeyRing(secRing, "single-secret-keyring.pgp");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
