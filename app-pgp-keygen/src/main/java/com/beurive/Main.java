// This example illustrates the creation of keys and key rings.

package com.beurive;

import java.lang.IllegalArgumentException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.io.IOException;
import java.security.Security;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.util.Iterator;

import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

    /**
     * Create a ArmoredOutputStream to a file.
     * @param inPath Path to the file.
     * @return a new ArmoredOutputStream.
     * @throws IOException
     */

    private static ArmoredOutputStream getOutputStream(String inPath) throws IOException {
        return new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(new File(inPath))));
    }

    /**
     * Dump a given keyring into a file identified by its path.
     * @param inKeyRing The keyring to dump.
     * @param inPath Path to the target file.
     * @throws IOException
     */

    private static void DumpKeyRing(PGPKeyRing inKeyRing, String inPath) throws IOException {
        ArmoredOutputStream outputStream = getOutputStream(inPath);
        inKeyRing.encode(outputStream);
        outputStream.close();
    }

    /**
     * Dump a given public key into a file identified by its path.
     * @param inPublicKey The public key to dump.
     * @param inPath Path to the target file.
     * @throws IOException
     */

    private static void DumpPublicKey(PGPPublicKey inPublicKey, String inPath) throws IOException {
        ArmoredOutputStream outputStream = getOutputStream(inPath);
        inPublicKey.encode(outputStream);
        outputStream.close();
    }

    /**
     * Dump a given secret key into a file identified by its path.
     * @param inSecreteKey The secret key to dump.
     * @param inPath Path to the target file.
     * @throws IOException
     */

    private static void DumpSecretKey(PGPSecretKey inSecreteKey, String inPath) throws IOException {
        ArmoredOutputStream outputStream = getOutputStream(inPath);
        inSecreteKey.encode(outputStream);
        outputStream.close();
    }

    /**
     * Dump all (public) keys within a given public keyring.
     * @param inKeyRing The public keyring to dump.
     * @param inPathPrefix The path prefix of the target file.
     * @throws IOException
     */

    private static void DumpAllPublicKeys(PGPPublicKeyRing inKeyRing,
                                          String inPathPrefix) throws IOException {
        Iterator<PGPPublicKey> pubIterator = inKeyRing.iterator();
        int id = 1;
        while (true) {
            if (! pubIterator.hasNext()) break;
            DumpPublicKey(pubIterator.next(), inPathPrefix + id++ + ".pgp");
        }
    }

    /**
     * Dump all (secret) keys within a given secret keyring.
     * @param inKeyRing The secret keyring to dump.
     * @param inPathPrefix The path prefix of the target file.
     * @throws IOException
     */

    private static void DumpAllSecretKeys(PGPSecretKeyRing inKeyRing,
                                          String inPathPrefix) throws IOException {
        Iterator<PGPSecretKey> pubIterator = inKeyRing.iterator();
        int id = 1;
        while (true) {
            if (! pubIterator.hasNext()) break;
            DumpSecretKey(pubIterator.next(), inPathPrefix + id++ + ".pgp");
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

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                inPairs[0],
                inIdentity,
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(inPairs[0].getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase)
        );

        for (int i=1; i<inPairs.length; i++) {
            keyRingGen.addSubKey(inPairs[i]);
        }
        return keyRingGen;
    }

    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());

        try {
            PGPKeyPair RsaKeyPair = createRsaKeyPair();
            PGPKeyPair DsaKeyPair = createDsaKeyPair();
            PGPKeyPair ElGamalKeyPair = createElGamalKeyPair();

            // Create the keyring generator.
            PGPKeyPair[] keyPairs = {RsaKeyPair, DsaKeyPair, ElGamalKeyPair};
            PGPKeyRingGenerator keyRingGen = getKeyRingGenerator(keyPairs,
                    "denis@email.com",
                    "password");

            // Generate the PGP keys.
            PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
            PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

            // Dump everything.
            DumpKeyRing(pubRing, "public-keyring.pgp");
            DumpKeyRing(secRing, "secret-keyring.pgp");
            DumpAllPublicKeys(pubRing, "public-key-");
            DumpAllSecretKeys(secRing, "secret-key-");
        } catch (Exception e) {
            System.out.println("Error: " + e.toString());
        }
    }
}
