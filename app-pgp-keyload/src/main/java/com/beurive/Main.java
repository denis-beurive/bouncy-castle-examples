package com.beurive;

import java.io.*;
import java.security.Security;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;


public class Main {

    private static ArmoredInputStream get_stream(String in_path) throws IOException {
        return new ArmoredInputStream(new BufferedInputStream(new FileInputStream(new File(in_path))));
    }

    public static void main(String[] args) {

        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());


        // Save everything into files.
        try {

            ArmoredInputStream inputStream;
            PGPObjectFactory pgpObjectFactory;
            Object pgpObject;

            // Load the public key ring.
            inputStream = get_stream("./data/public-key.pgp");
            pgpObjectFactory = new PGPObjectFactory(
                    inputStream, new JcaKeyFingerprintCalculator());

            while ((pgpObject = pgpObjectFactory.nextObject()) != null) {
                System.out.println("> " + pgpObject.getClass().getName());
                PGPPublicKeyRing publicKeyRing = (PGPPublicKeyRing)pgpObject;
            }
            inputStream.close();

            // Load the secret key ring.
            inputStream = get_stream("./data/secret-key.pgp");
            pgpObjectFactory = new PGPObjectFactory(
                    inputStream, new JcaKeyFingerprintCalculator());

            while ((pgpObject = pgpObjectFactory.nextObject()) != null) {
                System.out.println("> " + pgpObject.getClass().getName());
                PGPSecretKeyRing secretKeyRing = (PGPSecretKeyRing)pgpObject;
            }
            inputStream.close();

        } catch (IOException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }
    }
}
