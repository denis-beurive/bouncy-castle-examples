// This example illustrates the creation of keys and key rings.

package com.beurive;

import java.io.*;
import java.lang.IllegalArgumentException;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.beurive.pgp.Key;
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
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;


public class Main {

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
        OutputStream stream = new FileOutputStream(new File(inPath));
        if (asArmored) {
            stream = new ArmoredOutputStream(stream);
        }

        inKeyRing.encode(stream);
        stream.close();
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
        PGPSignatureSubpacketGenerator subPacketGenerator = new PGPSignatureSubpacketGenerator();
        subPacketGenerator.setKeyExpirationTime(false, 1000000);
        subPacketGenerator.setExportable(false, true);
        subPacketGenerator.setRevocable(false, true);

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
                subPacketGenerator.generate(),
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
     * Add a Primary Key Binding Signature (tag=2, type=0x19) to a given public key.
     * @param inPublicSubkey The public key.
     * @param inSigningPrivateKey The private key used to generate the signature.
     * This should be the private key associated to the master key.
     * @return The method returns the signed public key.
     * @throws PGPException
     */

    static public PGPPublicKey addPrimaryKeyBindingSignature(PGPPublicKey inPublicSubkey,
                                                             PGPPrivateKey inSigningPrivateKey) throws PGPException {

        // Define subpackets.
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.setSignatureCreationTime(false, new Date());

        // Create the signature generator.
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(
                        inPublicSubkey.getAlgorithm(),
                        HashAlgorithmTags.SHA1));
        signatureGenerator.init(PGPSignature.PRIMARYKEY_BINDING, inSigningPrivateKey);
        signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());

        return PGPPublicKey.addCertification(inPublicSubkey, signatureGenerator.generate());
    }

    /**
     * Generate a secret key using the following data:
     * * a public key.
     * * the private key associated with the given public key.
     * * the passphrase that protects the private key.
     *
     * Please note that a public key and its associated secret key
     * are intrinsically linked. This method does not generate a
     * (secret) key. It generates a (secret key) packet. A secret key
     * should have been generated, along with the given public key,
     * prior to the call to this method.
     *
     * This method is intended to be called after a public key packet
     * is modified. For example, a signature has been applied to a
     * public key packet (within a public key), and you want to generate
     * a new secret key that includes the updated public key packet.
     *
     * @param inPublicKey The public key.
     * @param inSigningPrivateKey The private key associated to the given
     * public key.
     * @param inPassPhrase The passphrase that protects the private key.
     * @return The method returns a new secret key.
     * @throws PGPException
     */

    static private PGPSecretKey createSecretKey(PGPPublicKey inPublicKey,
                                                PGPPrivateKey inSigningPrivateKey,
                                                char[] inPassPhrase) throws PGPException {

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA256);
        PBESecretKeyEncryptor encryptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc).setProvider("BC").build(inPassPhrase);
        // NOTES:
        // * Other versions of the constructor "PGPSecretKey" exist.
        //   These other versions allow the definition of subpackets.
        // * Please note the value of the fourth parameter (false).
        //   This value means that the generated secret key is a subkey.
        return new PGPSecretKey(inSigningPrivateKey, inPublicKey, sha1Calc, false, encryptor);
    }

    /**
     * Create a secret subkey designed to be added to a given keyring.
     * @param inSecretKeyRing The keyring into which the new key will be added.
     * @param inKeyPairToAdd The pair of keys to add.
     * @param inPassPhrase The passphrase that protects the secret keyring content.
     * @return The method returns a new secret subkey.
     * @throws PGPException
     */

    static PGPSecretKey createSecretSubKey(PGPSecretKeyRing inSecretKeyRing,
                                           PGPKeyPair inKeyPairToAdd,
                                           String inPassPhrase) throws PGPException {

        char[] passPhrase = inPassPhrase.toCharArray();
        PGPKeyPair[] keyPs = new PGPKeyPair[2];

        PGPPublicKey publicMasterKey = inSecretKeyRing.getPublicKey();
        PGPPrivateKey privateMasterKey = Key.extractPrivateKey(inSecretKeyRing.getSecretKey(), passPhrase);
        keyPs[0] = new PGPKeyPair(publicMasterKey, privateMasterKey);
        keyPs[1] = inKeyPairToAdd;

        List<PGPSecretKey> secretKeys = new ArrayList<>();
        String userId = publicMasterKey.getUserIDs().next();
        PGPKeyRingGenerator generator = getKeyRingGenerator(keyPs, userId, inPassPhrase);
        generator.generateSecretKeyRing().getSecretKeys().forEachRemaining(secretKeys::add);
        return secretKeys.get(1);
    }

    /**
     * Generate a signing subkey.
     * @param inMasterSecretKey The master key the generated subkey is bound to.
     * @param inPassPhrase The passphrase that protects the master key.
     * @return The method returns a new signing subkey bound to the given master key.
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */

    static public PGPSecretKey createSigningSubKey(
            PGPSecretKey inMasterSecretKey,
            String inPassPhrase)
            throws IOException, PGPException, NoSuchProviderException, NoSuchAlgorithmException {

        PBESecretKeyDecryptor masterDecryptor = new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(inPassPhrase.toCharArray());
        PGPDigestCalculator checksumCalculator = new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build().get(HashAlgorithmTags.SHA1);
        JcePBESecretKeyEncryptorBuilder keyEncryptorBuilder = new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256);
        JcaPGPContentSignerBuilder certificationSignerBuilder = new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_SIGN, HashAlgorithmTags.SHA256).setProvider("BC");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        JcaPGPKeyPair signSubKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_SIGN,
                kpg.generateKeyPair(),
                new Date());
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_SIGN,
                        HashAlgorithmTags.SHA256).setProvider("BC"));
        signatureGenerator.init(PGPSignature.PRIMARYKEY_BINDING, signSubKeyPair.getPrivateKey());

        PGPSignatureSubpacketGenerator subGen = new PGPSignatureSubpacketGenerator();
        subGen.setEmbeddedSignature(false, signatureGenerator.generateCertification(inMasterSecretKey.getPublicKey(), signSubKeyPair.getPublicKey()));

        PGPSecretKey secretSigSubKey = new PGPSecretKey(
                inMasterSecretKey.extractKeyPair(masterDecryptor),
                signSubKeyPair,
                checksumCalculator,
                subGen.generate(),
                null,
                certificationSignerBuilder,
                keyEncryptorBuilder.build(inPassPhrase.toCharArray()));

        return secretSigSubKey;
    }

    /**
     * Generate an encryption subkey.
     * @param inMasterSecretKey The master key the generated subkey is bound to.
     * @param inPassPhrase The passphrase that protects the master key.
     * @return The method returns a new encryption subkey bound to the given master key.
     * @throws PGPException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */

    static public PGPSecretKey createEncryptionSubKey(PGPSecretKey inMasterSecretKey,
                                                      String inPassPhrase)
            throws PGPException,
            NoSuchProviderException,
            NoSuchAlgorithmException {
        PBESecretKeyDecryptor masterDecryptor = new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(inPassPhrase.toCharArray());
        PGPDigestCalculator checksumCalculator = new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build().get(HashAlgorithmTags.SHA1);
        JcePBESecretKeyEncryptorBuilder keyEncryptorBuilder = new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256);
        JcaPGPContentSignerBuilder certificationSignerBuilder = new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_SIGN, HashAlgorithmTags.SHA256).setProvider("BC");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        PGPSecretKey secretEncSubKey = new PGPSecretKey(
                inMasterSecretKey.extractKeyPair(masterDecryptor),
                new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_ENCRYPT, kpg.generateKeyPair(), new Date()),
                checksumCalculator,
                null,
                null,
                certificationSignerBuilder,
                keyEncryptorBuilder.build(inPassPhrase.toCharArray()));
        return secretEncSubKey;
    }


    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        final int separatorLength = 50;
        Security.addProvider(new BouncyCastleProvider());
        final String ownerId = "owner@email.com";
        final String passPhrase = "password";
        final String publicKeyRing1ArmoredPath = "data/public-keyring1.pgp";
        final String secretKeyRing1ArmoredPath = "data/secret-keyring1.pgp";
        final String publicKeyRing2ArmoredPath = "data/public-keyring2.pgp";
        final String secretKeyRing2ArmoredPath = "data/secret-keyring2.pgp";
        final String signingSubkeyPath = "data/signing-subkey.pgp";
        final String encryptSubkeyPath = "data/encrypt-subkey.pgp";

        try {
            // -------------------------------------------------------
            // Create a key ring with 3 key pairs.
            // -------------------------------------------------------

            System.out.printf("%s\n", "=".repeat(separatorLength));
            System.out.printf("Create a keyring\n");
            System.out.printf("%s\n\n", "=".repeat(separatorLength));

            // Create the master key.
            PGPKeyPair masterRsaKeyPair = createRsaKeyPair();
            PGPPrivateKey masterPrivateKey = masterRsaKeyPair.getPrivateKey();

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

            System.out.println("Keys:");
            List<PGPSecretKey> secretKeys = getSecretKeyIds(secRing);
            for (PGPSecretKey k: secretKeys) {
                System.out.printf("\t\t[%X] algo=%d (is master ? %s, is signing ? %s)\n", k.getKeyID(), k.getKeyEncryptionAlgorithm(), k.isMasterKey() ? "yes" : "no", k.isSigningKey() ? "yes" : "no");
            }
            System.out.printf("\n");

            System.out.printf("Create the armored public key ring 1 \"%s\"\n", publicKeyRing1ArmoredPath);
            System.out.printf("Create the armored secret key ring 1 \"%s\"\n", secretKeyRing1ArmoredPath);
            dumpKeyRing(pubRing, publicKeyRing1ArmoredPath, true);
            dumpKeyRing(secRing, secretKeyRing1ArmoredPath, true);
            System.out.printf(">> gpg --list-packet %s\n", publicKeyRing1ArmoredPath);
            System.out.printf(">> gpg --list-packet %s\n", secretKeyRing1ArmoredPath);

            // -------------------------------------------------------
            // Add a subkey to a keyring.
            // -------------------------------------------------------

            System.out.printf("\n%s\n", "=".repeat(separatorLength));
            System.out.printf("Create a new subkey\n");
            System.out.printf("Add Primary Key Binding Signature to the subkey\n");
            System.out.printf("Add the subkey to the keyring\n");
            System.out.printf("%s\n\n", "=".repeat(separatorLength));

            // Create a secret subkey designed to be added to the keyring.
            PGPSecretKey newSecretSubKey = createSecretSubKey(secRing, createRsaKeyPair(), passPhrase);

            // Add a Primary Key Binding Signature (tag=2, type=0x19) to the previously created secret key.
            newSecretSubKey = createSecretKey(
                    addPrimaryKeyBindingSignature(newSecretSubKey.getPublicKey(), masterPrivateKey),
                    Key.extractPrivateKey(newSecretSubKey, passPhrase.toCharArray()),
                    passPhrase.toCharArray());

            // Add the new subkey to the keyring.
            pubRing = PGPPublicKeyRing.insertPublicKey(pubRing, newSecretSubKey.getPublicKey());
            secRing = PGPSecretKeyRing.insertSecretKey(secRing, newSecretSubKey);

            System.out.println("Keys:");
            secretKeys = getSecretKeyIds(secRing);
            for (PGPSecretKey k: secretKeys) {
                System.out.printf("\t\t[%X] algo=%d (is master ? %s, is signing ? %s)\n", k.getKeyID(), k.getKeyEncryptionAlgorithm(), k.isMasterKey() ? "yes" : "no", k.isSigningKey() ? "yes" : "no");
            }
            System.out.printf("\n");

            System.out.printf("Create the armored public key ring 2 \"%s\"\n", publicKeyRing2ArmoredPath);
            System.out.printf("Create the armored secret key ring 2 \"%s\"\n", secretKeyRing2ArmoredPath);
            dumpKeyRing(pubRing, publicKeyRing2ArmoredPath, true);
            dumpKeyRing(secRing, secretKeyRing2ArmoredPath, true);
            System.out.printf(">> gpg --list-packet %s\n", publicKeyRing2ArmoredPath);
            System.out.printf(">> gpg --list-packet %s\n", secretKeyRing2ArmoredPath);

            System.out.printf("Generate a signing subkey \"%s\"\n", encryptSubkeyPath);
            PGPSecretKey signingSubKey = createSigningSubKey(secRing.getSecretKey(), passPhrase);
            Key.dumpSecretKey(signingSubKey, encryptSubkeyPath);
            System.out.printf("Is the generated key a subkey ? %s\n", (! signingSubKey.isMasterKey()) ? "yes" : "no");
            System.out.printf("Is the generated key a signing ? %s\n", signingSubKey.isSigningKey() ? "yes" : "no");

            System.out.printf("Generate an encryption subkey \"%s\"\n", signingSubkeyPath);
            PGPSecretKey encryptSubKey = createEncryptionSubKey(secRing.getSecretKey(), passPhrase);
            Key.dumpSecretKey(encryptSubKey, signingSubkeyPath);
            System.out.printf("Is the generated key a subkey ? %s\n", (! encryptSubKey.isMasterKey()) ? "yes" : "no");
            System.out.printf("Is the generated key an encryption key ? %s\n", (! encryptSubKey.isSigningKey()) ? "yes" : "no");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
