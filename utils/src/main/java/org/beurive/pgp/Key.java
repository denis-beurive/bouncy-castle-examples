package org.beurive.pgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class Key {

    /**
     * Extract the private key from a given secret key.
     * @param pgpSecKey The secret key.
     * @param passPhrase The private key pass phrase.
     * @return The private key.
     * @throws PGPException
     */

    public static PGPPrivateKey extractPrivateKey(PGPSecretKey pgpSecKey, char[] passPhrase)
            throws PGPException {
        PGPPrivateKey privateKey = null;
        BcPGPDigestCalculatorProvider calculatorProvider = new BcPGPDigestCalculatorProvider();
        BcPBESecretKeyDecryptorBuilder secretKeyDecryptorBuilder = new BcPBESecretKeyDecryptorBuilder(calculatorProvider);
        PBESecretKeyDecryptor pBESecretKeyDecryptor = secretKeyDecryptorBuilder.build(passPhrase);
        return pgpSecKey.extractPrivateKey(pBESecretKeyDecryptor);
    }

    /**
     * Dump a given public key into a file identified by its path.
     * @param inPublicKey The public key to dump.
     * @param inPath Path to the output file.
     * @throws IOException
     */

    public static void dumpPublicKey(PGPPublicKey inPublicKey, String inPath) throws IOException {
        ArmoredOutputStream outputStream = new ArmoredOutputStream(new FileOutputStream(new File(inPath)));
        inPublicKey.encode(outputStream);
        outputStream.close();
    }

    /**
     * Dump a given secret key into a file identified by its path.
     * @param inSecreteKey The secret key to dump.
     * @param inPath Path prefix used to create the output file paths.
     * @throws IOException
     * @throws PGPException
     */

    public static void dumpSecretKey(PGPSecretKey inSecreteKey,
                                      String inPath) throws IOException {
        ArmoredOutputStream outputSecretKeyStream = new ArmoredOutputStream(new FileOutputStream(new File(inPath)));
        inSecreteKey.encode(outputSecretKeyStream);
        outputSecretKeyStream.close();
    }

    /**
     * Dump the components of a secret key into a file identified by its path.
     * @param inSecreteKey The secret key to dump.
     * @param inPathPrefix The path prefix.
     * @param inPassPhrase The passphrase that protects the private key.
     * @throws IOException
     * @throws PGPException
     */

    public static void dumpSecretKeyComponent(PGPSecretKey inSecreteKey,
                                              String inPathPrefix,
                                              char[] inPassPhrase) throws IOException, PGPException {
        PGPPrivateKey privateKey = extractPrivateKey(inSecreteKey, inPassPhrase);
        BCPGKey packet = privateKey.getPrivateKeyDataPacket();

        if (packet instanceof org.bouncycastle.bcpg.RSASecretBCPGKey) {
            // @see org.bouncycastle.bcpg.RSASecretBCPGKey.encode
            // This will dump 4 MPIs.
            BCPGOutputStream outputStream = new BCPGOutputStream(new BufferedOutputStream(new FileOutputStream(new File(inPathPrefix + "-private-rsa.data"))));
            org.bouncycastle.bcpg.RSASecretBCPGKey key = (org.bouncycastle.bcpg.RSASecretBCPGKey)packet;
            key.encode(outputStream);
            outputStream.close();
        }

        if (packet instanceof org.bouncycastle.bcpg.DSASecretBCPGKey) {
            // @see org.bouncycastle.bcpg.DSASecretBCPGKey.encode
            // This will dump 1 MPI.
            BCPGOutputStream outputStream = new BCPGOutputStream(new BufferedOutputStream(new FileOutputStream(new File(inPathPrefix + "-private-dsa.data"))));
            org.bouncycastle.bcpg.DSASecretBCPGKey key = (org.bouncycastle.bcpg.DSASecretBCPGKey)packet;
            key.encode(outputStream);
            outputStream.close();
        }

        if (packet instanceof org.bouncycastle.bcpg.ElGamalSecretBCPGKey) {
            // @see org.bouncycastle.bcpg.ElGamalSecretBCPGKey.encode
            // This will dump 1 MPI.
            BCPGOutputStream outputStream = new BCPGOutputStream(new BufferedOutputStream(new FileOutputStream(new File(inPathPrefix + "-private-elgamal.data"))));
            org.bouncycastle.bcpg.ElGamalSecretBCPGKey key = (org.bouncycastle.bcpg.ElGamalSecretBCPGKey)packet;
            key.encode(outputStream);
            outputStream.close();
        }
    }
}
