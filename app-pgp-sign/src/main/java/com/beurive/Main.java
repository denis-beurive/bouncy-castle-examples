package com.beurive;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.io.IOException;
import java.security.Security;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.File;

import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

    /**
     * Get an ArmoredOutputStream to file identified by its given path.
     * @param inPath Pah to the file to create.
     * @return An ArmoredOutputStream to the file which path was given.
     * @throws IOException
     */
    private static ArmoredOutputStream getStream(String inPath) throws IOException {
        return new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(new File(inPath))));
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

    public static void main(String[] args) {

        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());

        // Create the keyring generator.
        String identity = "denis@email.com";
        char[] passPhrase = "password".toCharArray();

        PGPKeyRingGenerator keyRingGen = null;
        try {
            PGPKeyPair rsaKeyPair1 = createRsaKeyPair();     // This will be the "master" key.
            PGPKeyPair rsaKeyPair2 = createDsaKeyPair();     // This will be a subkey.
            PGPKeyPair rsaKeyPair3 = createElGamalKeyPair(); // This will be a subkey.

            PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
            keyRingGen = new PGPKeyRingGenerator(
                    PGPSignature.POSITIVE_CERTIFICATION,
                    rsaKeyPair1,
                    identity,
                    sha1Calc,
                    null,
                    null,
                    new JcaPGPContentSignerBuilder(rsaKeyPair1.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                    new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase)
            );

            keyRingGen.addSubKey(rsaKeyPair2);
            keyRingGen.addSubKey(rsaKeyPair3);
        } catch (PGPException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }

        // Generate the PGP keys.
        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

        // Save everything into files.
        try {
            ArmoredOutputStream outputStream;

            // Save the public key ring into a file.
            outputStream = getStream("public-keyring.pgp");
            pubRing.encode(outputStream);
            outputStream.close();

            // Save the secrete key ring into a file.
            outputStream = getStream("secret-keyring.pgp");
            secRing.encode(outputStream);
            outputStream.close();
        } catch (IOException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }
    }
}
