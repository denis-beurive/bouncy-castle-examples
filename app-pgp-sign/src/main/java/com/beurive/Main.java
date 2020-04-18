package com.beurive;

import java.io.*;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

    /**
     * Get an ArmoredInputStream to file identified by its given path.
     * @param in_path Path to the file to create.
     * @return An ArmoredInputStream to the file which path was given.
     * @throws IOException
     */

    private static ArmoredInputStream getArmoredInputStream(String in_path) throws IOException {
        return new ArmoredInputStream(new BufferedInputStream(new FileInputStream(new File(in_path))));
    }

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
     * Load a secret key ring from a given file.
     * @param inPath Path to the secret key ring.
     * @return The secret key ring.
     * @throws IOException
     * @throws NullPointerException
     */

    private static PGPSecretKeyRing loadSecretKeyRing(String inPath)
            throws IOException, NullPointerException {
        // Load the secret key ring.
        ArmoredInputStream inputStream = getArmoredInputStream(inPath);
        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(
                inputStream, new JcaKeyFingerprintCalculator());

        Object pgpObject;
        PGPSecretKeyRing secretKeyRing = null;
        while ((pgpObject = pgpObjectFactory.nextObject()) != null) {
            System.out.println(pgpObject.getClass().getName());
            secretKeyRing = (PGPSecretKeyRing)pgpObject;
        }
        inputStream.close();
        return secretKeyRing;
    }

    /**
     * Sign a document with a given secret key.
     * @param inDocumentToSign The document to sign.
     * @param inOutputFilePath The path to the signature file.
     * @param inKeyRingPath The path to the key ring.
     * @param inPassPhrase The passphrase used to activate the secret key.
     * @throws IOException
     * @throws PGPException
     */

    static public void sign(String inDocumentToSign,
                            String inOutputFilePath,
                            String inKeyRingPath,
                            String inPassPhrase) throws IOException, PGPException {

        byte[] messageCharArray = inDocumentToSign.getBytes();
        char[] passPhrase = inPassPhrase.toCharArray();

        // Load the private key.
        PGPSecretKeyRing secretKeyRing = loadSecretKeyRing(inKeyRingPath);
        PGPPrivateKey privateKey = secretKeyRing.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase));

        // Create a signature generator.
        int keyAlgorithm = privateKey.getPublicKeyPacket().getAlgorithm();
        int hashAlgorithm = PGPUtil.SHA1;
        PGPSignatureGenerator signerGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm).setProvider("BC")
        );
        signerGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        // Set the user IDs.
        Iterator<String> it = secretKeyRing.getPublicKey().getUserIDs();
        while (it.hasNext()) {
            String userId = it.next();
            System.out.println("Add <" + userId + ">");
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            // If you look at the code of the method "setSignerUserID()", then you see that this method can be called more than once:
            //    list.add(new SignerUserID(isCritical, userID));
            // This, it is possible to set more than one user ID.
            spGen.setSignerUserID(false, userId);
            signerGenerator.setHashedSubpackets(spGen.generate());
        }

        PGPCompressedDataGenerator zlibDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
        ArmoredOutputStream armoredOutputStream = getArmoredOutputStream(inOutputFilePath);

        // BCPGOutputStream: Basic output stream.
        BCPGOutputStream bOut = new BCPGOutputStream(zlibDataGenerator.open(armoredOutputStream));
        signerGenerator.generateOnePassVersion(false).encode(bOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE, messageCharArray.length, new Date());

        for (byte c : messageCharArray) {
            lOut.write(c);
            signerGenerator.update(c);
        }

        lOut.close();
        lGen.close();

        signerGenerator.generate().encode(bOut);
        zlibDataGenerator.close();
        armoredOutputStream.close();
    }

    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());
        String documentToSign = "Message to sign";
        String passPhrase = "password";

        try {
            sign(documentToSign,
                    "./data/signature.pgp",
                    "./data/secret-key.pgp",
                    passPhrase);
        } catch (IOException | PGPException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }
    }
}
