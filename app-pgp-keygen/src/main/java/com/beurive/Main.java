// This example illustrates the creation of keys and key rings.

package com.beurive;

import java.io.*;
import java.lang.IllegalArgumentException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.security.Security;
import java.util.Iterator;
import java.util.List;

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
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
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
     * @param inPath Path to the output file.
     * @param asArmored Tell whether the output file should be
     * dumped as an armored ASCII file or not. The value true means
     * "dump as armored ASCII text."
     * @throws IOException
     */

    private static void dumpKeyRing(PGPKeyRing inKeyRing, String inPath, boolean asArmored) throws IOException {
        OutputStream stream;
        if (asArmored) {
            stream = getArmoredOutputStream(inPath);
        } else {
            stream = new FileOutputStream(new File(inPath));
        }

        inKeyRing.encode(stream);
        stream.close();
    }

    /**
     * Extract the private key from a given secret key.
     * @param pgpSecKey The secret key.
     * @param passPhrase The private key pass phrase.
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
            throw new PGPException(String.format("Invalid private key pass phrase \"%s\": %s",
                    String.valueOf(passPhrase),
                    e.toString()));
        }

        return privateKey;
    }

    /**
     * Dump a given public key into a file identified by its path.
     * @param inPublicKey The public key to dump.
     * @param inPath Path to the output file.
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
     * @param inPathPrefix Path prefix used to create the output file paths.
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
     * Dump all (public) keys within a given public key-ring.
     * @param inKeyRing The public keyring to dump.
     * @param inPathPrefix The path prefix used to create the output files.
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
     * Dump all (secret) keys within a given secret key-ring.
     * @param inKeyRing The secret keyring to dump.
     * @param inPathPrefix The path prefix used to create the output file paths.
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
     * Create an RSA key pair.
     * @return An RSA key pair.
     * @throws PGPException
     * @note You should set the strength of the key to at least 1024.
     * @see https://stackoverflow.com/questions/2678138/is-there-a-size-restriction-on-signatures-in-java-java-security
     */

    private static PGPKeyPair createRsaKeyPair() throws PGPException {
        // Create a key pair generator for RSA.
        RSAKeyPairGenerator rsaKpg = new RSAKeyPairGenerator();
        BigInteger publicExponent = BigInteger.valueOf(0x11);
        SecureRandom random = new SecureRandom();
        // **WARNING**: You should set the strength of the key to at least 1024.
        // see https://stackoverflow.com/questions/2678138/is-there-a-size-restriction-on-signatures-in-java-java-security
        int strength = 1024;
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
     * @note It seems that GPG rejects short DSA keys (512 bytes us too short).
     * You should specify 2048 bytes.
     */

    private static PGPKeyPair createDsaKeyPair() throws PGPException {
        DSAParametersGenerator dsaPGen = new DSAParametersGenerator();
        // **WARNING**: It seems that GPG rejects short DSA keys (512 bytes us too short).
        // You should specify (at least) 2048 bytes.
        int size = 2048;
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

        // Define subpackets.
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.setKeyExpirationTime(false, 1000000);
        subpacketGenerator.setExportable(false, true);
        subpacketGenerator.setRevocable(false, true);

        // See RFC 4840: [9.4. Hash Algorithms]
        // https://tools.ietf.org/html/rfc4880#section-9.4
        // Note: only SHA1 supported for key checksum calculations
        // org.bouncycastle.openpgp.PGPException: only SHA1 supported for key checksum calculations.
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA256);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                // See RFC 4880: [5.2.1. Signature Types]
                // https://tools.ietf.org/html/rfc4880#section-5.2.1
                // PGPSignature.POSITIVE_CERTIFICATION,
                PGPSignature.DEFAULT_CERTIFICATION, // 0x10
                inPairs[0],
                inIdentity,
                sha1Calc,
                subpacketGenerator.generate(),
                null,
                new JcaPGPContentSignerBuilder(inPairs[0].getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc).setProvider("BC").build(passPhrase)
        );

        for (int i=1; i<inPairs.length; i++) {
            // NOTE ID:
            // Another version of the method "addSubKey" exists.
            // This other version accepts subpackets.
            keyRingGen.addSubKey(inPairs[i]);
        }
        return keyRingGen;
    }

    /**
     * Return the list of secret keys in a given secret ring.
     * @param inSecretKeyRing The secret key ring.
     * @return The list of key IDs.
     */

    static private List<PGPSecretKey> getSecretKeyIds(PGPSecretKeyRing inSecretKeyRing) {
        Iterator<PGPSecretKey> it = inSecretKeyRing.getSecretKeys();
        List<PGPSecretKey> ids = new ArrayList<PGPSecretKey>();
        while(it.hasNext()) {
            ids.add(it.next());
        }
        return ids;
    }

    /**
     * Sign a key.
     * @param inSecretKey The secret key to sign.
     * @param inSigningPrivateKey The private key used to sign.
     * @param inPassPhrase The passphrase used to protect the newly created private key.
     * @throws PGPException
     * @throws IOException
     */

    static private PGPSecretKey signKey(PGPSecretKey inSecretKey,
                                        PGPPrivateKey inSigningPrivateKey,
                                        char[] inPassPhrase) throws PGPException {

        PGPPublicKey pubKey = inSecretKey.getPublicKey();

        // Define subpackets.
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.setKeyExpirationTime(false, 1000000);
        subpacketGenerator.setExportable(false, true);
        subpacketGenerator.setRevocable(false, true);

        // Create the signature generator.
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(
                        inSecretKey.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA1));
        signatureGenerator.init(PGPSignature.PRIMARYKEY_BINDING, inSigningPrivateKey);
        signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA256);
        PBESecretKeyEncryptor encryptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc).setProvider("BC").build(inPassPhrase);

        PGPPublicKey signedPublicKey = PGPPublicKey.addCertification(pubKey, signatureGenerator.generate());
        // NOTE ID:
        // Other versions of the constructor "PGPSecretKey" exist.
        // These other versions allow the definition of subpackets.
        PGPSecretKey signedSecretKey = new PGPSecretKey(inSigningPrivateKey, signedPublicKey, sha1Calc, false, encryptor);

        return signedSecretKey;
    }

    /**
     * Add a subkey to a given keyring.
     * @param inSecretKeyRing The keyring into which the new key will be added.
     * @param inKeyPairToAdd The pair of keys to add.
     * @param inPassPhrase The passphrase for the secret keyring.
     * @return A new keyring.
     * @throws PGPException
     */

    static PGPKeyRingGenerator addSubKey(PGPSecretKeyRing inSecretKeyRing,
                                         PGPKeyPair inKeyPairToAdd,
                                         String inPassPhrase) throws PGPException {

        char[] passPhrase = inPassPhrase.toCharArray();

        List<PGPKeyPair> keyPairs = new ArrayList<PGPKeyPair>();
        Iterator<PGPSecretKey> secretKeyIterator = inSecretKeyRing.getSecretKeys();
        while (secretKeyIterator.hasNext()) {
            PGPSecretKey secretKey = secretKeyIterator.next();
            PGPPrivateKey privateKey = extractPrivateKey(secretKey, passPhrase);
            PGPPublicKey publicKey = secretKey.getPublicKey();
            PGPKeyPair kp = new PGPKeyPair(publicKey, privateKey);
            keyPairs.add(kp);
        }
        keyPairs.add(inKeyPairToAdd);
        PGPKeyPair[] keyPs = new PGPKeyPair[keyPairs.size()];
        keyPairs.toArray(keyPs);

        String userId = inSecretKeyRing.getSecretKey().getUserIDs().next();
        return getKeyRingGenerator(keyPs, userId, inPassPhrase);
    }


    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());
        String ownerId = "owner@email.com";
        String passPhrase = "password";
        String publicKeyRing1ArmoredPath = "data/public-keyring1-armored.pgp";
        String secretKeyRing1ArmoredPath = "data/secret-keyring1-armored.pgp";
        String publicKeyRing1BinPath = "data/public-keyring1-bin.pgp";
        String secretKeyRing1BinPath = "data/secret-keyring1-bin.pgp";
        String publicKey1PrefixPath = "data/public-key1-";
        String secretKey1PrefixPath = "data/secret-key1-";
        String publicKeyRing2ArmoredPath = "data/public-keyring2-armored.pgp";
        String secretKeyRing2ArmoredPath = "data/secret-keyring2-armored.pgp";
        String publicKeyRing2BinPath = "data/public-keyring2-bin.pgp";
        String secretKeyRing2BinPath = "data/secret-keyring2-bin.pgp";
        String publicKey2PrefixPath = "data/public-key2-";
        String secretKey2PrefixPath = "data/secret-key2-";
        String signedPublicKeyPath = "data/signed-public-key.pgp";
        String signedSecretKeyPrefixPath = "data/signed-secret-key";

        try {
            // -------------------------------------------------------
            // Create a key ring with 3 key pairs.
            // -------------------------------------------------------

            System.out.printf("%s\n\n", "=".repeat(30));

            // Create the master key.
            PGPKeyPair masterRsaKeyPair = createRsaKeyPair();
            // **WARNING**: sub-keys of type DSA cannot be "cross-certified" using GPG 2.2.19.
            // If you don't use PGP, then you can create a DSA sub-key:
            // PGPKeyPair subKeyPair1 = createDsaKeyPair();
            PGPKeyPair subKeyPair1 = createRsaKeyPair();
            PGPKeyPair subKeyPair2 = createElGamalKeyPair();
            PGPKeyPair[] keyPairs1 = {masterRsaKeyPair, subKeyPair1, subKeyPair2};
            PGPKeyRingGenerator keyRingGen = getKeyRingGenerator(keyPairs1,
                    ownerId,
                    passPhrase);

            // Generate the PGP keys.
            PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
            PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

            // -------------------------------------------------------
            // Dump information.
            // -------------------------------------------------------

            System.out.println("Keys:");
            List<PGPSecretKey> secretKeys = getSecretKeyIds(secRing);
            for (PGPSecretKey k: secretKeys) {
                System.out.printf("\t\t[%X] algo=%d (is master ? %s, is signing ? %s)\n", k.getKeyID(), k.getKeyEncryptionAlgorithm(), k.isMasterKey() ? "yes" : "no", k.isSigningKey() ? "yes" : "no");
            }
            System.out.printf("* algo: %s\n", "https://tools.ietf.org/html/rfc4880#section-9.2\n\n");

            System.out.printf(String.format("Create the armored public key ring 1 \"%s\"\n", publicKeyRing1ArmoredPath));
            System.out.printf(String.format("Create the armored secret key ring 1 \"%s\"\n", secretKeyRing1ArmoredPath));
            dumpKeyRing(pubRing, publicKeyRing1ArmoredPath, true);
            dumpKeyRing(secRing, secretKeyRing1ArmoredPath, true);

            System.out.printf(String.format("Create the binary public key ring 1 \"%s\"\n", publicKeyRing1BinPath));
            System.out.printf(String.format("Create the binary secret key ring 1 \"%s\"\n", secretKeyRing1BinPath));
            dumpKeyRing(pubRing, publicKeyRing1BinPath, false);
            dumpKeyRing(secRing, secretKeyRing1BinPath, false);

            dumpAllPublicKeys(pubRing, publicKey1PrefixPath);
            dumpAllSecretKeys(secRing, secretKey1PrefixPath, passPhrase);

            // -------------------------------------------------------
            // Add a subkey to a keyring.
            // -------------------------------------------------------

            System.out.printf("\n%s\n\n", "=".repeat(30));

            PGPKeyPair keysToBeAdded = createRsaKeyPair();
            keyRingGen = addSubKey(secRing, keysToBeAdded, passPhrase);
            pubRing = keyRingGen.generatePublicKeyRing();
            secRing = keyRingGen.generateSecretKeyRing();

            // -------------------------------------------------------
            // Dump information.
            // -------------------------------------------------------

            System.out.println("Keys:");
            secretKeys = getSecretKeyIds(secRing);
            for (PGPSecretKey k: secretKeys) {
                System.out.printf("\t\t[%X] algo=%d (is master ? %s, is signing ? %s)\n", k.getKeyID(), k.getKeyEncryptionAlgorithm(), k.isMasterKey() ? "yes" : "no", k.isSigningKey() ? "yes" : "no");
            }
            System.out.printf("* algo: %s\n", "https://tools.ietf.org/html/rfc4880#section-9.2\n\n");

            System.out.printf(String.format("Create the armored public key ring 2 \"%s\"\n", publicKeyRing2ArmoredPath));
            System.out.printf(String.format("Create the armored secret key ring 2 \"%s\"\n", secretKeyRing2ArmoredPath));
            dumpKeyRing(pubRing, publicKeyRing2ArmoredPath, true);
            dumpKeyRing(secRing, secretKeyRing2ArmoredPath, true);

            System.out.printf(String.format("Create the binary public key ring 2 \"%s\"\n", publicKeyRing2BinPath));
            System.out.printf(String.format("Create the binary secret key ring 2 \"%s\"\n", secretKeyRing2BinPath));
            dumpKeyRing(pubRing, publicKeyRing2BinPath, false);
            dumpKeyRing(secRing, secretKeyRing2BinPath, false);

            dumpAllPublicKeys(pubRing, publicKey2PrefixPath);
            dumpAllSecretKeys(secRing, secretKey2PrefixPath, passPhrase);

            // -------------------------------------------------------
            // Sign secret key.
            // -------------------------------------------------------

            System.out.printf("\n%s\n\n", "=".repeat(30));

            List<PGPSecretKey> secretKeyList = new ArrayList<>();
            Iterator<PGPSecretKey> secretKeyIterator = secRing.getSecretKeys();
            secretKeyIterator.forEachRemaining(secretKeyList::add);
            PGPSecretKey secretMasterKey = secretKeyList.get(0);
            PGPSecretKey secretKeyToSign = secretKeyList.get(1);
            PGPPrivateKey signingPrivateKey = extractPrivateKey(secretMasterKey, passPhrase.toCharArray());
            PGPSecretKey signedKey = signKey(secretKeyToSign, signingPrivateKey, passPhrase.toCharArray());

            System.out.printf("Secret master key ID: %X\n", secretMasterKey.getKeyID());
            System.out.printf("Secret subkey ID:     %X\n", secretKeyToSign.getKeyID());
            System.out.printf("Signed public key: %s\n", signedPublicKeyPath);
            System.out.printf("Signed secret key: %s\n", signedSecretKeyPrefixPath);

            dumpPublicKey(signedKey.getPublicKey(), signedPublicKeyPath);
            dumpSecretKey(signedKey, signedSecretKeyPrefixPath, passPhrase.toCharArray());


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
