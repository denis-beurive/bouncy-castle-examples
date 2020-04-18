// This file illustrates the encryption process.
//
// This code is inspired from:
// - org.bouncycastle.openpgp.examples.KeyBasedFileProcessor
// - org.bouncycastle.openpgp.examples.PGPExampleUtil
//
// see org.bouncycastle.openpgp.examples.PGPExampleUtil


package com.beurive;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.OutputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;
import java.util.Iterator;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;


public class Main {

    /**
     * Loads a file, compress it, and returns its compressed content as an array of bytes.
     * @param filePath The path to the file to load.
     * @param algorithm The compression algorithm to use.
     * @return An array of bytes that represents the content of the file.
     * @throws IOException
     */

    static byte[] compressFile(String filePath, int algorithm) throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(filePath));
        comData.close();
        return bOut.toByteArray();
    }

    /**
     * Opens a key ring file and loads the first available key suitable for encryption.
     * @param input Data stream containing the public key data.
     * @return The first public key found.
     * @throws IOException
     * @throws PGPException
     */

    static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        // We just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.

        Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = keyRingIter.next();
            Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = keyIter.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    /**
     * Load a public key from a keyring identified by its path.
     * @param filePath The path to the file that contains the keyring.
     * @return A public key.
     * @throws IOException
     * @throws PGPException
     */

    static PGPPublicKey readPublicKey(String filePath) throws IOException, PGPException
    {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(filePath));
        PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();
        return pubKey;
    }

    /**
     * Encrypt a file identified by its path and store the result into an output file.
     * @param outputFilePath Path to the output (encrypted) file.
     * @param inputFilePath Path to the file en encrypt.
     * @param keyringPath Path to the file that contains the public keyring.
     *                    The first public usable for encryption will be used.
     * @param armor Flag that tells the method whether the encrypted data should be armored or not.
     * @param withIntegrityCheck Flag that tells whether or not the resulting encrypted data will be protected using an
     *                           integrity packet.
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws PGPException
     */

    private static void encryptFile(
            String          outputFilePath,
            String          inputFilePath,
            String          keyringPath,
            boolean         armor,
            boolean         withIntegrityCheck)
            throws IOException, NoSuchProviderException, PGPException
    {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFilePath));
        PGPPublicKey encKey = readPublicKey(keyringPath);
        encryptFile(out, inputFilePath, encKey, armor, withIntegrityCheck);
        out.close();
    }

    /**
     * Encrypt a file identified by its path and store the result into an output file.
     * @param out Output stream to the output (encrypted) file.
     * @param inputFilePath Path to the file to encrypt.
     * @param encryptionKey The public key to use for encryption.
     * @param armor Flag that tells the method whether the encrypted data should be armored or not.
     * @param withIntegrityCheck Flag that tells whether or not the resulting encrypted data will be protected using an
     *                           integrity packet.
     * @throws IOException
     */

    private static void encryptFile(
            OutputStream    out,
            String          inputFilePath,
            PGPPublicKey    encryptionKey,
            boolean         armor,
            boolean         withIntegrityCheck)
            throws IOException
    {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        try {
            byte[] bytes = compressFile(inputFilePath, CompressionAlgorithmTags.ZIP);

            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BC"));

            OutputStream cOut = encGen.open(out, bytes.length);

            cOut.write(bytes);
            cOut.close();

            if (armor) {
                out.close();
            }
        }
        catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    public static void main(String[] args) {

        String inputFile = "data/file-to-encrypt.txt";
        String outputFile = "data/encrypted-file.pgp";
        String keyRingFile = "data/public-keyring.pgp";

        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());

        try {
            encryptFile(outputFile, inputFile, keyRingFile, true, true);
        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
        }
    }
}
