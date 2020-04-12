package com.beurive;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.io.IOException;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.encoders.Hex;
import org.beurive.Packet;

public class Main {


    public static void main(String[] args) {

        // ------------------------------------------------------------------
        // Generate "Key Material Packet" (see section 5.5 of the RFC 4880)
        // - the public key packet.
        // - the private key packet.
        // ------------------------------------------------------------------

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

        // Generate the keys.
        AsymmetricCipherKeyPair rsaKp = rsaKpg.generateKeyPair();
        PGPKeyPair rsaKeyPair = null;
        try {
            rsaKeyPair = new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKp, new Date());
        } catch (PGPException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }

        PGPPublicKey publicKey = rsaKeyPair.getPublicKey();
        PGPPrivateKey privateKey = rsaKeyPair.getPrivateKey();

        // ------------------------------------------------------------------
        // Public key (see section 5.5.2 of the RFC 4880)
        // ------------------------------------------------------------------

        System.out.println("Public key");
        System.out.println("==========\n");
        System.out.println("Fingerprint:     " + new String(Hex.encode(publicKey.getFingerprint())));
        System.out.println("ID:              " + publicKey.getKeyID());
        System.out.println("Algorithm:       " + publicKey.getAlgorithm() + ". See RFC 4880 - section 9.1 <Public-Key Algorithms>: 1 => RSA (Encrypt or Sign)");
        System.out.println("Creation time:   " + publicKey.getCreationTime().toString());
        System.out.println("Is encryption:   " + (publicKey.isEncryptionKey() ? "yes" : "no"));
        System.out.println("Has revocation:  " + (publicKey.hasRevocation() ? "yes" : "no"));
        System.out.println("OpenPGP version: " + publicKey.getVersion() + " . See RFC 4880 - section 5.2.2 <Public-Key Packet Formats>");

        byte[] content = null;
        try {
            content = publicKey.getEncoded();
        } catch (IOException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }
        System.out.println("Length         : " + content.length + "\n");
        System.out.println(new String(Hex.encode(content)) + "\n");

        System.out.println("Packet explorer:");
        System.out.println(Packet.dump_header(content) + "\n");


        // ------------------------------------------------------------------
        // Private key (see section 5.5.3 of the RFC 4880)
        // ------------------------------------------------------------------

        System.out.println("Private key:");
        System.out.println("\tID: " + privateKey.getKeyID());



        char[] passPhrase = "password".toCharArray();

    }
}
