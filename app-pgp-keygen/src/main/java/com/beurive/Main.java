package com.beurive;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.io.IOException;
import java.security.Security;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

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


    public static void main(String[] args) {

        // Declare the provider "BC" (for Bouncy Castle).
        // new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase)
        Security.addProvider(new BouncyCastleProvider());

        byte[] content = null;

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

        try {
            content = publicKey.getEncoded();
        } catch (IOException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }

        System.out.println("Public key");
        System.out.println("==========\n");
        System.out.println("Fingerprint:     " + "0x" + new String(Hex.encode(publicKey.getFingerprint())));
        System.out.println("ID:              " + "0x" + Long.toHexString(publicKey.getKeyID()));
        System.out.println("Algorithm:       " + publicKey.getAlgorithm() + ". See RFC 4880 - section 9.1 <Public-Key Algorithms>: 1 => RSA (Encrypt or Sign)");
        System.out.println("Creation time:   " + publicKey.getCreationTime().toString());
        System.out.println("Is encryption:   " + (publicKey.isEncryptionKey() ? "yes" : "no"));
        System.out.println("Has revocation:  " + (publicKey.hasRevocation() ? "yes" : "no"));
        System.out.println("OpenPGP version: " + publicKey.getVersion() + " . See RFC 4880 - section 5.2.2 <Public-Key Packet Formats>");
        System.out.println("Length:          " + content.length + "\n");
        System.out.println(Hex.toHexString(content) + "\n");
        System.out.println("Packet explorer:");
        System.out.println(Packet.dump_header(content) + "\n");

        // ------------------------------------------------------------------
        // Private key (see section 5.5.3 of the RFC 4880)
        //
        // A Secret-Key packet contains all the information that is found in
        // a Public-Key packet, including the public-key material, but also
        // includes the secret-key material after all the public-key fields.
        // ------------------------------------------------------------------

        content = privateKey.getPrivateKeyDataPacket().getEncoded();
        System.out.println("Private key");
        System.out.println("===========\n");
        System.out.println("ID:            " + "0x" + Long.toHexString(privateKey.getKeyID()));
        System.out.println("Packet format: " + privateKey.getPrivateKeyDataPacket().getFormat());
        System.out.println("length:        " + content.length + "\n");
        System.out.println(Hex.toHexString(content));

        // ------------------------------------------------------------------
        // Generate the keyring
        // ------------------------------------------------------------------

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


        try {
            PGPSecretKey s1 = secRing.getSecretKey();
            ArmoredOutputStream outputStream = new ArmoredOutputStream(
                    new BufferedOutputStream(
                            new FileOutputStream(
                                    new File("secret-key.key"))));
            s1.encode(outputStream);
            outputStream.close();

        } catch (FileNotFoundException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        } catch (IOException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }
    }
}
