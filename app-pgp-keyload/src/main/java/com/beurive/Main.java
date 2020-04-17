package com.beurive;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.security.Security;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class Main {

    /**
     * Create an ArmoredInputStream from a given file identifier bu its path.
     * @param in_path The path of the file.
     * @return A new ArmoredInputStream.
     * @throws IOException
     */

    private static ArmoredInputStream getInputStream(String in_path) throws IOException {
        return new ArmoredInputStream(new BufferedInputStream(new FileInputStream(new File(in_path))));
    }

    /**
     * Load a PGP document from a file. The document may be:
     * - a key.
     * - a key ring.
     * - a collection of key rings.
     * - an encrypted document.
     *
     * @param inDocumentPath The path to the document to load.
     * @return The method returns a list og objects.
     * @throws IOException
     */

    static private List<Object> LoadPgpDocuments(String inDocumentPath) throws IOException {
        Object pgpObject;
        List<Object> pgpObjects = new ArrayList<Object>();

        ArmoredInputStream inputStream = getInputStream(inDocumentPath);

        // Create an object factory suitable for reading PGP objects such as keys,
        // key rings and key ring collections, or PGP encrypted data.

        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(
                inputStream, new JcaKeyFingerprintCalculator());

        while ((pgpObject = pgpObjectFactory.nextObject()) != null) {
            pgpObjects.add(pgpObject);
        }
        inputStream.close();
        return pgpObjects;
    }

    public static void main(String[] args) {

        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());

        try {
            List<Object> objects;

            objects = LoadPgpDocuments("./data/public-key-1.pgp");
            for (Object o: objects) {
                System.out.println(o.getClass().getName());
                PGPPublicKeyRing publicKeyRingKeyRing = (PGPPublicKeyRing)o;
            }

            objects = LoadPgpDocuments("./data/public-key-2.pgp");
            for (Object o: objects) {
                System.out.println(o.getClass().getName());
                PGPPublicKey publicKey = (PGPPublicKey)o;
            }

            objects = LoadPgpDocuments("./data/public-key-3.pgp");
            for (Object o: objects) {
                System.out.println(o.getClass().getName());
                PGPPublicKey publicKey = (PGPPublicKey)o;
            }

            objects = LoadPgpDocuments("./data/public-keyring.pgp");
            for (Object o: objects) {
                System.out.println(o.getClass().getName());
                PGPPublicKeyRing publicKeyRing = (PGPPublicKeyRing)o;
            }

            objects = LoadPgpDocuments("./data/secret-keyring.pgp");
            for (Object o: objects) {
                System.out.println(o.getClass().getName());
                PGPSecretKeyRing secretKeyRing = (PGPSecretKeyRing)o;
            }
        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }
    }
}
