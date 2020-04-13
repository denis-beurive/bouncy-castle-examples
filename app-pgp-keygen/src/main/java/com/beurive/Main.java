package com.beurive;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.io.IOException;
import java.security.Security;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.File;

import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
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
import org.bouncycastle.openpgp.PGPSecretKey;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import org.beurive.Packet;

public class Main {

    private static ArmoredOutputStream get_stream(String in_path) throws IOException {
        return new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(new File(in_path))));
    }

    public static void main(String[] args) {

        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());

        byte[] content = null;

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
        PGPKeyPair rsaKeyPair = null;
        try {
            rsaKeyPair = new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKp, new Date());
        } catch (PGPException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }

        PGPPublicKey publicRsaKey = rsaKeyPair.getPublicKey();
        PGPPrivateKey privateRsaKey = rsaKeyPair.getPrivateKey();

        // Public key (see section 5.5.2 of the RFC 4880)
        System.out.println("Public key");
        System.out.println("  Fingerprint:     " + "0x" + new String(Hex.encode(publicRsaKey.getFingerprint())));
        System.out.println("  ID:              " + "0x" + Long.toHexString(publicRsaKey.getKeyID()));
        System.out.println("  Algorithm:       " + publicRsaKey.getAlgorithm() + ". See RFC 4880 - section 9.1 <Public-Key Algorithms>: 1 => RSA (Encrypt or Sign)");
        System.out.println("  Creation time:   " + publicRsaKey.getCreationTime().toString());
        System.out.println("  Is encryption:   " + (publicRsaKey.isEncryptionKey() ? "yes" : "no"));
        System.out.println("  Has revocation:  " + (publicRsaKey.hasRevocation() ? "yes" : "no"));
        System.out.println("  OpenPGP version: " + publicRsaKey.getVersion() + " . See RFC 4880 - section 5.2.2 <Public-Key Packet Formats>\n");

        // Private key (see section 5.5.3 of the RFC 4880)
        System.out.println("Private key");
        System.out.println("  ID:            " + "0x" + Long.toHexString(privateRsaKey.getKeyID()));
        System.out.println("  Packet format: " + privateRsaKey.getPrivateKeyDataPacket().getFormat() + "\n");

        // Create the keyring generator.
        String identity = "denis@email.com";
        char[] passPhrase = "password".toCharArray();

        PGPKeyRingGenerator keyRingGen = null;
        try {
            PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
            keyRingGen = new PGPKeyRingGenerator(
                    PGPSignature.POSITIVE_CERTIFICATION,
                    rsaKeyPair,
                    identity,
                    sha1Calc,
                    null,
                    null,
                    new JcaPGPContentSignerBuilder(rsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                    new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase)
            );
        } catch (PGPException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }

        // Generate the PGP keys.
        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

        try {
            System.out.println(Packet.dump_header(pubRing.getEncoded()));
        } catch (IOException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }

        try {
            System.out.println(Packet.dump_header(secRing.getEncoded()));
        } catch (IOException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }

        // Save everything into files.
        try {

            ArmoredOutputStream outputStream;

            // Save the public key into a file.
            PGPPublicKey publicPgpKey = pubRing.getPublicKey();
            outputStream = get_stream("public-key.pgp");
            publicPgpKey.encode(outputStream);
            outputStream.close();

            // Save the secret key into a file.
            PGPSecretKey secretPgpKey = secRing.getSecretKey();
            outputStream = get_stream("secret-key.pgp");
            secretPgpKey.encode(outputStream);
            outputStream.close();

            // Save the public key ring into a file.
            outputStream = get_stream("public-keyring.pgp");
            pubRing.encode(outputStream);
            outputStream.close();

            // Save the secrete key ring into a file.
            outputStream = get_stream("secret-keyring.pgp");
            secRing.encode(outputStream);
            outputStream.close();
        } catch (IOException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }
    }
}
