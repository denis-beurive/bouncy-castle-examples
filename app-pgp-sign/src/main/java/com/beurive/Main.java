package com.beurive;

import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.File;
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

    private static ArmoredInputStream getInputStream(String in_path) throws IOException {
        return new ArmoredInputStream(new BufferedInputStream(new FileInputStream(new File(in_path))));
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
        ArmoredInputStream inputStream = getInputStream(inPath);
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


    public static void main(String[] args) {

        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());
        byte[] messageCharArray = "Message to sign".getBytes();

        // Load the private key.
        char[] passPhrase = "password".toCharArray();
        PGPSecretKeyRing secretKeyRing = null;
        PGPPrivateKey privateKey = null;

        try {
            secretKeyRing = loadSecretKeyRing("./data/secret-key.pgp");
            // Unlock the private key.
            privateKey = secretKeyRing.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase));
        } catch (PGPException | IOException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }

        // Create a signature generator.
        int keyAlgorithm = privateKey.getPublicKeyPacket().getAlgorithm();
        int hashAlgorithm = PGPUtil.SHA1;
        PGPSignatureGenerator signerGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(
                        keyAlgorithm, hashAlgorithm).setProvider("BC"));

        try {
            signerGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        } catch (PGPException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }

        Iterator<String> it = secretKeyRing.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            String userId = it.next();
            System.out.println("Add <" + userId + ">");
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, userId);
            signerGenerator.setHashedSubpackets(spGen.generate());
        }

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedData.ZLIB);

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = encOut;
        out = new ArmoredOutputStream(out);
        OutputStream lOut = null;
        PGPLiteralDataGenerator lGen = null;
        BCPGOutputStream bOut = null;

        try {
            bOut = new BCPGOutputStream(comData.open(out));

            signerGenerator.generateOnePassVersion(false).encode(bOut);

            lGen = new PGPLiteralDataGenerator();
            lOut = lGen.open(bOut, PGPLiteralData.BINARY,
                    PGPLiteralData.CONSOLE, messageCharArray.length, new Date());

            for (byte c : messageCharArray) {
                lOut.write(c);
                signerGenerator.update(c);
            }

            lOut.close();
            lGen.close();

            signerGenerator.generate().encode(bOut);
            comData.close();
            out.close();

            System.out.println(encOut.toString());

        } catch (IOException | PGPException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }
    }
}
