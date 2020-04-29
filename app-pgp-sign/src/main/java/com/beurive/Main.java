package com.beurive;

import java.io.*;
import java.security.Security;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
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
import org.bouncycastle.openpgp.PGPOnePassSignature;
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
            secretKeyRing = (PGPSecretKeyRing)pgpObject;
        }
        inputStream.close();
        return secretKeyRing;
    }

    /**
     * Extract the master private key from a given secret key ring.
     * @param inSecretKeyRing The secret key ring.
     * @param inPassPhrase The passphrase required for the private key.
     * @return The master private key.
     * @throws PGPException
     */

    static private PGPPrivateKey getMasterPrivateKey(PGPSecretKeyRing inSecretKeyRing,
                                                    String inPassPhrase) throws PGPException {
        return inSecretKeyRing.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(inPassPhrase.toCharArray()));
    }

    /**
     * Extract a private key identified by its ID, from a given secret key ring.
     * @param inSecretKeyRing The secret key ring.
     * @param inPassPhrase The passphrase required for the private key.
     * @param inKeyId The secret key ID.
     * @return If a secret key with the given ID exists, and if this key can be used to sign a document, then the corresponding private key is returned.
     * Otherwise, the method returns the value null.
     * @throws PGPException
     */

    static private PGPPrivateKey getPrivateKey(PGPSecretKeyRing inSecretKeyRing,
                                              String inPassPhrase,
                                              long inKeyId) throws PGPException {
        PGPSecretKey key = inSecretKeyRing.getSecretKey(inKeyId);
        if (null == key) {
            return null;
        }
        if (! key.isSigningKey()) {
            return null;
        }
        return key.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(inPassPhrase.toCharArray()));
    }

    /**
     * Return the list secret keys in a secret ring identified by its path.
     * @param inKeyRingPath The path to the key ring.
     * @return The list of key IDs.
     */

    static private List<PGPSecretKey> getSecretKeyIds(String inKeyRingPath) throws IOException {
        PGPSecretKeyRing secretKeyRing = loadSecretKeyRing(inKeyRingPath);
        Iterator<PGPSecretKey> it = secretKeyRing.getSecretKeys();
        List<PGPSecretKey> ids = new ArrayList<PGPSecretKey>();
        while(it.hasNext()) {
            ids.add(it.next());
        }
        return ids;
    }

    /**
     * Sign a document with a given secret key.
     *
     * Remember that a PGP signature contains:
     * - a literal data packet (the document that is being signed).
     * - a signature.
     *
     * ┌───────────────────────┐
     * │ Literal data packet   │
     * ├───────────────────────┤
     * │ Signature scaffolding │
     * └───────────────────────┘
     *
     * @param inDocumentToSign A string that represents the content of the document to sign.
     * @param inOutputFilePath The path to the signature file.
     * @param inKeyRingPath The path to the secret key ring.
     * @param inSecretKeyId The ID of the secret key to use.
     * If the given value is 0, then the master key is used.
     * @param inPassPhrase The passphrase used to activate the secret key.
     * @throws IOException
     * @throws PGPException
     */

    static public void sign(String inDocumentToSign,
                            String inOutputFilePath,
                            String inKeyRingPath,
                            long inSecretKeyId,
                            String inPassPhrase) throws IOException, PGPException {

        byte[] messageCharArray = inDocumentToSign.getBytes();

        // Load the private key.
        PGPSecretKeyRing secretKeyRing = loadSecretKeyRing(inKeyRingPath);
        PGPPrivateKey privateKey;
        if (0 == inSecretKeyId) {
            privateKey = getMasterPrivateKey(secretKeyRing, inPassPhrase);
        } else {
            privateKey = getPrivateKey(secretKeyRing, inPassPhrase, inSecretKeyId);
            if (null == privateKey) {
                System.out.printf("ERROR: no secret key with ID %X exists, or this key cannot be used for signing!\n", inSecretKeyId);
                System.exit(1);
            }
        }

        // Create a signature generator.
        int keyAlgorithm = privateKey.getPublicKeyPacket().getAlgorithm();
        int hashAlgorithm = PGPUtil.SHA256;
        PGPSignatureGenerator signerGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm).setProvider("BC")
        );
        signerGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        // Set the user IDs.
        Iterator<String> it = secretKeyRing.getPublicKey().getUserIDs();
        while (it.hasNext()) {
            String userId = it.next();
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            // If you look at the code of the method "setSignerUserID()", then you see that this method can be called more than once:
            //    list.add(new SignerUserID(isCritical, userID));
            // This, it is possible to set more than one user ID.
            spGen.setSignerUserID(false, userId);
            signerGenerator.setHashedSubpackets(spGen.generate());
        }

        PGPCompressedDataGenerator compressDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);

        // BCPGOutputStream: Basic output stream.
        //
        // Note:
        //  - org.bouncycastle.openpgp.PGPCompressedDataGenerator.open(java.io.OutputStream):
        //    Return an OutputStream which will save the data being written to the compressed
        //    object.
        // - org.bouncycastle.openpgp.PGPSignatureGenerator.generateOnePassVersion:
        //    Return the one pass header associated with the current signature.
        //    -> PGPOnePassSignature (A one pass signature object)
        // - org.bouncycastle.openpgp.PGPOnePassSignature.encode:
        //    Write a OnePassSignaturePacket (generic signature object) into the output stream.
        //    If you look at the class OnePassSignaturePacket, you will recognise the structure of
        //    a signature packet, as defined by the RFC 4880 (https://tools.ietf.org/html/rfc4880#section-5.2).

        ArmoredOutputStream armoredOutputStream = getArmoredOutputStream(inOutputFilePath);
        BCPGOutputStream basicOut = new BCPGOutputStream(compressDataGenerator.open(armoredOutputStream));
        PGPOnePassSignature signature = signerGenerator.generateOnePassVersion(false);
        signature.encode(basicOut);

        // ┌───────────────────────┐
        // │ Signature scaffolding │ >> basicOut
        // └───────────────────────┘
        //
        // Result:
        //
        // signerGenerator
        // ┊
        // ┌───────────────────────┐
        // │ Signature scaffolding │
        // └───────────────────────┘

        // PGPLiteralDataGenerator: Generator for producing literal data packets.
        //
        // A Literal Data packet contains the body of a message; data that is not to be
        // further interpreted.
        //
        // see https://tools.ietf.org/html/rfc4880#section-5.9
        //
        // Note:
        //  - org.bouncycastle.openpgp.PGPLiteralDataGenerator.open(java.io.OutputStream, char, java.lang.String, long, java.util.Date)
        //    Open a literal data packet, returning a stream to store the data inside the packet.
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(
                basicOut,                // the underlying output stream to write the literal data packet to.
                PGPLiteralData.BINARY,   // the format of the literal data that will be written to the output stream.
                PGPLiteralData.CONSOLE,  // the name of the "file" to encode in the literal data object.
                                         // The special name indicating a "for your eyes only" packet.
                messageCharArray.length, // the length of the data that will be written.
                new Date());             // the time of last modification we want stored.

        // ┌─────────────────────┐
        // │ Literal data packet │ >> basicOut
        // └─────────────────────┘
        //
        // Result:
        //
        // lOut                   signerGenerator
        // ┊                      ┊
        // ┌─────────────────────┐┌───────────────────────┐
        // │ Literal data packet ││ Signature scaffolding │
        // └─────────────────────┘└───────────────────────┘

        // Write le literal data packet.
        lOut.write(messageCharArray);
        // Create the signature.
        signerGenerator.update(messageCharArray);

        // - org.bouncycastle.openpgp.PGPLiteralDataGenerator.open():
        //   The stream created can be closed off by either calling close() on the stream or close() on
        //   the generator. Closing the returned stream does not close off the OutputStream parameter out.
        //
        // -> "basicOut" is not closed ! It is flushed.
        //    see org.bouncycastle.openpgp.WrappedGeneratorStream.close -> close "lGen".
        //    see org.bouncycastle.openpgp.PGPLiteralDataGenerator.close -> "basicOut" is not closed
        lOut.close();
        // lGen.close(); // Should not be necessary.

        // - org.bouncycastle.openpgp.PGPSignatureGenerator.generate:
        //   Return a signature object containing the current signature state.
        // - org.bouncycastle.openpgp.PGPSignature.encode(java.io.OutputStream, boolean):
        //   Encode the signature to outStream, with trust packets stripped out if forTransfer is true.
        //
        // -> Generate the (fully calculated) signature and send it to "basicOut".
        signerGenerator.generate().encode(basicOut);
        compressDataGenerator.close();
        armoredOutputStream.close();
    }

    /**
     * Generate a detached signature.
     * @param inInputFilePath Path to the file from which a signature will be generated.
     * @param inOutputFilePath Path to the output file.
     * @param inKeyRingPath Path to the secret key.
     * @param inSecretKeyId The ID of the secret key to use.
     * If the given value is 0, then the master key is used.
     * @param inPassPhrase Passphrase required for the secret key.
     * @throws IOException
     * @throws PGPException
     */

    static public void detachSign(String inInputFilePath,
                                  String inOutputFilePath,
                                  String inKeyRingPath,
                                  long inSecretKeyId,
                                  String inPassPhrase) throws IOException, PGPException {

        FileInputStream input = new FileInputStream(inInputFilePath);
        byte[] messageCharArray = input.readAllBytes();
        char[] passPhrase = inPassPhrase.toCharArray();

        // Load the private key.
//        PGPSecretKeyRing secretKeyRing = loadSecretKeyRing(inKeyRingPath);
//        PGPPrivateKey privateKey = secretKeyRing.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase));
//
//        // Load the private key.
        PGPSecretKeyRing secretKeyRing = loadSecretKeyRing(inKeyRingPath);
        PGPPrivateKey privateKey;
        if (0 == inSecretKeyId) {
            privateKey = getMasterPrivateKey(secretKeyRing, inPassPhrase);
        } else {
            privateKey = getPrivateKey(secretKeyRing, inPassPhrase, inSecretKeyId);
            if (null == privateKey) {
                System.out.printf("ERROR: no secret key with ID %X exists, or this key cannot be used for signing!\n", inSecretKeyId);
                System.exit(1);
            }
        }


        // Create a signature generator.
        int keyAlgorithm = privateKey.getPublicKeyPacket().getAlgorithm();
        int hashAlgorithm = PGPUtil.SHA256;
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm).setProvider("BC")
        );
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        // Set the user IDs.
        Iterator<String> it = secretKeyRing.getPublicKey().getUserIDs();
        while (it.hasNext()) {
            String userId = it.next();
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            // If you look at the code of the method "setSignerUserID()", then you see that this method can be called more than once:
            //    list.add(new SignerUserID(isCritical, userID));
            // This, it is possible to set more than one user ID.
            spGen.setSignerUserID(false, userId);
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }

        // BCPGOutputStream: Basic output stream.
        ArmoredOutputStream armoredOutputStream = getArmoredOutputStream(inOutputFilePath);
        BCPGOutputStream basicOut = new BCPGOutputStream(armoredOutputStream);

        // Create the signature.
        signatureGenerator.update(messageCharArray);
        signatureGenerator.generate().encode(basicOut);
        armoredOutputStream.close();
    }


    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        String result;
        Security.addProvider(new BouncyCastleProvider());
        String documentToSign = "Message to sign";
        String passPhrase = "password";
        String secretKeyRing = "./data/secret-keyring.pgp";
        String fileToSign = "./data/document-to-sign.txt";

        try {
            // Print the list of key IDs in the secret key ring.
            System.out.printf("List of key IDs in the key ring \"%s\":\n", secretKeyRing);
            List<PGPSecretKey> keys = getSecretKeyIds(secretKeyRing);
            for (PGPSecretKey k: keys) {
                System.out.printf("\t- %016X (sign ? %s, master ? %s)\n",
                        k.getKeyID(),
                        k.isSigningKey() ? "yes" : "no",
                        k.isMasterKey() ? "yes" : "no");
            }

            // Sign with the master key.
            result = "./data/signature-master.pgp";
            System.out.printf("Sign <%s> using the master key => \"%s\".\n", documentToSign, result);
            sign(documentToSign,
                    result,
                    secretKeyRing,
                    0,
                    passPhrase);

            // Sign with a subkey.
            result = "./data/signature-subkey.pgp";
            System.out.printf("Sign <%s> using a sub key [%X] => \"%s\".\n", documentToSign, keys.get(1).getKeyID(), result);
            sign(documentToSign,
                    result,
                    secretKeyRing,
                    keys.get(1).getKeyID(),
                    passPhrase);

            // Detach sign with the master key.
            result = "./data/detached-signature-master.pgp";
            System.out.printf("Detach sign <%s> using the master key => \"%s\".\n", fileToSign, result);
            detachSign(fileToSign,
                    result,
                    secretKeyRing,
                    0,
                    passPhrase);

            // Detach sign with a sub key.
            result = "./data/detached-signature-subkey.pgp";
            System.out.printf("Detach sign <%s> using the sub key [%X] => \"%s\".\n", fileToSign, keys.get(1).getKeyID(), result);
            detachSign(fileToSign,
                    result,
                    secretKeyRing,
                    keys.get(1).getKeyID(),
                    passPhrase);

        } catch (IOException | PGPException e) {
            System.out.println("ERROR: " + e.toString());
            System.exit(1);
        }
    }
}
