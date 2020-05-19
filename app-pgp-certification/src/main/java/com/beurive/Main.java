// This file shows how to certify a key (using a signing secret key).

package com.beurive;

import java.security.Security;
import org.beurive.pgp.Key;
import org.beurive.pgp.Keyring;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;




public class Main {

    /**
     * Certify a public key.
     * @param inPublicKey The public key to certify.
     * @param inSigningPrivateKey The private key used to certify the public key.
     * @return The certified public key.
     * @throws PGPException
     */

    static private PGPPublicKey certifyPublicKey(PGPPublicKey inPublicKey,
                                                 PGPPrivateKey inSigningPrivateKey) throws PGPException {

        // Define subpackets.
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.setKeyExpirationTime(false, 1000000);
        subpacketGenerator.setExportable(false, true);
        subpacketGenerator.setRevocable(false, true);

        // Create the signature generator.
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(
                        inPublicKey.getAlgorithm(),
                        HashAlgorithmTags.SHA1));
        signatureGenerator.init(PGPSignature.PRIMARYKEY_BINDING, inSigningPrivateKey);
        signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());

        return PGPPublicKey.addCertification(inPublicKey, signatureGenerator.generate());
    }


    /**
     * Certify a secret key.
     * @param inSecretKey The secret key to sign.
     * @param inSigningPrivateKey The private key used to sign.
     * @param inPassPhrase The passphrase used to protect the newly created private key.
     * @return The certified secret key.
     * @throws PGPException
     */

    static private PGPSecretKey certifySecretKey(PGPSecretKey inSecretKey,
                                                 PGPPrivateKey inSigningPrivateKey,
                                                 char[] inPassPhrase) throws PGPException {

        PGPPublicKey pubKey = inSecretKey.getPublicKey();
        PGPPublicKey certifiedPubKey = certifyPublicKey(pubKey, inSigningPrivateKey);

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA256);
        PBESecretKeyEncryptor encryptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc).setProvider("BC").build(inPassPhrase);

        // Other versions of the constructor "PGPSecretKey" exist.
        // These other versions allow the definition of subpackets.
        return new PGPSecretKey(inSigningPrivateKey, certifiedPubKey, sha1Calc, false, encryptor);
    }


    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());
        String passPhrase = "password";
        String secretKeyRingPath = "data/secret-keyring.pgp";
        String publicKeyRingPath = "data/public-keyring.pgp";
        String certifiedSecretKeyPath = "data/certified-secret-key.pgp";
        String certifiedPublicKeyPath = "data/certified-public-key.pgp";

        try {
            // Load the secret keyring.
            PGPSecretKeyRing secretKeyRing = Keyring.loadSecretKeyring(secretKeyRingPath);
            PGPPublicKeyRing publicReyRing = Keyring.loadPublicKeyring(publicKeyRingPath);

            // Print the list of key IDs in the secret key ring.
            System.out.printf("List of key IDs in the key ring \"%s\":\n", secretKeyRingPath);
            PGPSecretKey[] keys = Keyring.getSecretKeys(Keyring.loadSecretKeyring(secretKeyRingPath), false);
            for (PGPSecretKey k: keys) {
                System.out.printf("\t- %016X (sign ? %s, master ? %s)\n",
                        k.getKeyID(),
                        k.isSigningKey() ? "yes" : "no",
                        k.isMasterKey() ? "yes" : "no");
            }

            // Get the required secret/private cryptographic documents.
            PGPSecretKey[] secretSigningKeys = Keyring.getSecretKeys(secretKeyRing, true);
            PGPSecretKey secretMasterKey = secretSigningKeys[0];
            PGPPrivateKey privateMasterKey = secretMasterKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase.toCharArray()));
            PGPSecretKey secretSubKey = secretSigningKeys[1];

            // Get the required public cryptographic documents.
            PGPPublicKey[] publicKeys = Keyring.getPublicKeys(publicReyRing);
            PGPPublicKey publicSubKey = publicKeys[1];

            // Certify the public subkey.
            System.out.printf("Certify subkey %X with master key %X => %s\n",
                    publicSubKey.getKeyID(),
                    secretMasterKey.getKeyID(),
                    certifiedPublicKeyPath);
            PGPPublicKey certifiedPubKey = certifyPublicKey(publicSubKey, privateMasterKey);
            Key.dumpPublicKey(certifiedPubKey, certifiedPublicKeyPath);

            // Certify the secret subkey.
            System.out.printf("Certify subkey %X with master key %X => %s\n",
                    secretSubKey.getKeyID(),
                    secretMasterKey.getKeyID(),
                    certifiedSecretKeyPath);
            PGPSecretKey certifiedKey = certifySecretKey(secretSubKey, privateMasterKey, passPhrase.toCharArray());
            Key.dumpSecretKey(certifiedKey, certifiedSecretKeyPath);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
