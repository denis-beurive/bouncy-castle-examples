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

import org.beurive.pgp.Key;
import org.beurive.pgp.Keyring;
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


public class Main {

    /**
     * Add a Positive Certification Signature (tag=2, type=0x13) to a given public key.
     * @param inPublicSubkey The public key.
     * @param inSigningPrivateKey The private key used to generate the signature.
     * This should be the private key associated to the master key.
     * @return The method returns the signed public key.
     * @throws PGPException
     */

    static public PGPPublicKey addPositiveCertificationSignature(PGPPublicKey inPublicSubkey,
                                                                 PGPPrivateKey inSigningPrivateKey) throws PGPException {

        // Define subpackets.
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.setSignatureCreationTime(false, new Date());

        // Create the signature generator.
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(
                        inPublicSubkey.getAlgorithm(),
                        HashAlgorithmTags.SHA1));
        signatureGenerator.init(PGPSignature.POSITIVE_CERTIFICATION, inSigningPrivateKey);
        signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());

        return PGPPublicKey.addCertification(inPublicSubkey, signatureGenerator.generate());
    }


    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());
        final String passPhrase = "password";
        final String bobSecKeyRingPath = "data/sec-bob.key";
        final String aliceSecKeyRingPath = "data/sec-alice.key";

        try {
            System.out.printf("Load Bob secret keyring %s\n", bobSecKeyRingPath);
            PGPSecretKeyRing bobSecKeyRing = Keyring.loadSecretKeyring(bobSecKeyRingPath);
            PGPSecretKey bobSecMasterKey = bobSecKeyRing.getSecretKey();
            PGPPrivateKey bobPrivMasterKey = Key.extractPrivateKey(bobSecMasterKey, passPhrase.toCharArray());

            System.out.printf("Load Alice secret keyring %s\n", aliceSecKeyRingPath);
            PGPSecretKeyRing aliceSecKeyRing  = Keyring.loadSecretKeyring(aliceSecKeyRingPath);
            PGPSecretKey aliceSecMasterKey = aliceSecKeyRing.getSecretKey();
            PGPPrivateKey alicePrivMasterKey = Key.extractPrivateKey(aliceSecMasterKey, passPhrase.toCharArray());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
