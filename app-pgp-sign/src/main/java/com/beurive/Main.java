package com.beurive;

import java.io.*;
import java.security.Security;

import java.security.Signature;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.beurive.pgp.UnexpectedDocumentException;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.beurive.pgp.Keyring;


public class Main {

    /**
     * Get an ArmoredInputStream from a file identified by its given path.
     * @param in_path Path to the input file.
     * @return An ArmoredInputStream from the file which path was given.
     * @throws IOException
     */

    private static ArmoredInputStream getArmoredInputStream(String in_path) throws IOException {
        return new ArmoredInputStream(new BufferedInputStream(new FileInputStream(new File(in_path))));
    }

    /**
     * Create a ArmoredOutputStream to a file.
     * @param inPath Path to the output file.
     * @return a new ArmoredOutputStream.
     * @throws IOException
     */

    private static ArmoredOutputStream getArmoredOutputStream(String inPath) throws IOException {
        return new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(new File(inPath))));
    }

    /**
     * Return the list secret keys in a secret ring identified by its path.
     * @param inKeyRingPath The path to the key ring.
     * @return The list of key IDs.
     */

    static private List<PGPSecretKey> getSecretKeyIds(String inKeyRingPath) throws IOException, UnexpectedDocumentException, PGPException {
        PGPSecretKeyRing secretKeyRing = Keyring.loadSecretKeyring(inKeyRingPath);
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
     * │ Signature             │
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
                            String inPassPhrase) throws IOException, PGPException, UnexpectedDocumentException {

        byte[] messageCharArray = inDocumentToSign.getBytes();

        // Load the private key.
        PGPSecretKeyRing secretKeyRing = Keyring.loadSecretKeyring(inKeyRingPath);
        PGPPrivateKey privateKey;
        if (0 == inSecretKeyId) {
            privateKey = Keyring.getMasterPrivateKey(secretKeyRing, inPassPhrase);
        } else {
            privateKey = Keyring.getPrivateKeyById(secretKeyRing, inSecretKeyId, inPassPhrase);
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
        PGPPublicKey pgpPublicMasterKey = secretKeyRing.getPublicKey();
        Iterator<String> it = pgpPublicMasterKey.getUserIDs();
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
                                  String inPassPhrase)
            throws IOException, PGPException, UnexpectedDocumentException {

        FileInputStream input = new FileInputStream(inInputFilePath);
        byte[] messageCharArray = input.readAllBytes();

        PGPSecretKeyRing secretKeyRing = Keyring.loadSecretKeyring(inKeyRingPath);
        PGPPrivateKey privateKey;
        if (0 == inSecretKeyId) {
            privateKey = Keyring.getMasterPrivateKey(secretKeyRing, inPassPhrase);
        } else {
            privateKey = Keyring.getPrivateKeyById(secretKeyRing, inSecretKeyId, inPassPhrase);
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

    private static boolean verifySignature(
            String inSignatureFile,
            PGPPublicKeyRing pubKeyRing)
            throws Exception
    {

        // The structure of the signature is:
        //
        // ┌───────────────────────────────────┐
        // │ One Pass Signature Packet (tag=4) │
        // └───────────────────────────────────┘
        // ┌───────────────────────────────────┐
        // │ Literal Data Packet (tag=11)      │
        // └───────────────────────────────────┘
        // ┌───────────────────────────────────┐
        // │ Signature Packet (tag=2)          │
        // └───────────────────────────────────┘
        //
        // See https://tools.ietf.org/html/rfc4880#section-5.4:
        //
        //     The One-Pass Signature packet precedes the signed data and contains
        //     enough information to allow the receiver to begin calculating any
        //     hashes needed to verify the signature. It allows the Signature
        //     packet to be placed at the end of the message, so that the signer
        //     can compute the entire signed message in one pass.
        //
        // The PGPOnePassSignature object contains the following data:
        //    - the signature type.
        //    - the hash algorithm used.
        //    - the public-key algorithm used.
        //    - the Key ID of the signing key.
        //    - a flag showing whether the signature is nested.
        //
        // Pleas note that, at this point, the PGPOnePassSignature object does **NOT**
        // contain the actual signature, nor the document that has been signed. These data
        // are needed to verify the signature.

        // Create a stream reader for PGP objects
        ArmoredInputStream armoredinputStream = getArmoredInputStream(inSignatureFile);
        PGPCompressedData data = new PGPCompressedData(armoredinputStream);
        BCPGInputStream basicIn = new BCPGInputStream(data.getDataStream());
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(basicIn);

        // Load the One Pass Signature Packet.
        // Get an input stream on the document that was signed (encoded within the Literal Data Packet).
        // Please keep in mind that the content of a Literal Data Packet is not encrypted.
        PGPOnePassSignatureList sigList = (PGPOnePassSignatureList)pgpFact.nextObject();
        PGPOnePassSignature onePassSignature = sigList.get(0);
        PGPLiteralData literalData = (PGPLiteralData)pgpFact.nextObject();
        InputStream literalDataStream = literalData.getInputStream();

        FileOutputStream out = new FileOutputStream(literalData.getFileName());
        PGPPublicKey key = pubKeyRing.getPublicKey(onePassSignature.getKeyID());
        onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

        int ch;
        while ((ch = literalDataStream.read()) >= 0)
        {
            // Push the signed document into the PGPOnePassSignature object.
            // This data is necessary in order to verify the signature.
            onePassSignature.update((byte)ch);
            // We create the file that was originally signed.
            out.write(ch);
        }

        out.close(); // Close the file that was originally signed.

        // [1] Load the signature.
        // [2] Inject it into the PGPOnePassSignature object.
        // ==> The PGPOnePassSignature object has everything it needs to verify the signature:
        //     - the signature type.
        //     - the hash algorithm used.
        //     - the public-key algorithm used.
        //     - the Key ID of the signing key.
        //     - a flag showing whether the signature is nested.
        //     - the document that has been signed.
        //     - the signature.
        // We can proceed to the verification.
        PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();

        return onePassSignature.verify(p3.get(0));
    }



    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());
        String documentToSign = "Message to sign";
        String passPhrase = "password";
        String secretKeyRing = "./data/secret-keyring.pgp";
        String publicKeyRing = "./data/public-keyring.pgp";
        String fileToSign = "./data/document-to-sign.txt";
        String sigMaster = "./data/signature-master.pgp";
        String sigSubKey = "./data/signature-subkey.pgp";
        String sigDetachedMaster = "./data/detached-signature-master.pgp";
        String sigDetachedSubKey = "./data/detached-signature-subkey.pgp";

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
            System.out.printf("Sign <%s> using the master key => \"%s\".\n", documentToSign, sigMaster);
            sign(documentToSign,
                    sigMaster,
                    secretKeyRing,
                    0,
                    passPhrase);

            // Sign with a subkey.
            System.out.printf("Sign <%s> using a sub key [%X] => \"%s\".\n", documentToSign, keys.get(1).getKeyID(), sigSubKey);
            sign(documentToSign,
                    sigSubKey,
                    secretKeyRing,
                    keys.get(1).getKeyID(),
                    passPhrase);

            // Detach sign with the master key.
            System.out.printf("Detach sign <%s> using the master key => \"%s\".\n", fileToSign, sigDetachedMaster);
            detachSign(fileToSign,
                    sigDetachedMaster,
                    secretKeyRing,
                    0,
                    passPhrase);

            // Detach sign with a sub key.
            System.out.printf("Detach sign <%s> using the sub key [%X] => \"%s\".\n", fileToSign, keys.get(1).getKeyID(), sigDetachedSubKey);
            detachSign(fileToSign,
                    sigDetachedSubKey,
                    secretKeyRing,
                    keys.get(1).getKeyID(),
                    passPhrase);

            // Verify the signature.

            if (verifySignature(sigMaster, Keyring.loadPublicKeyring(publicKeyRing))) {
                System.out.printf("The signature \"%s\" is valid.\n", sigMaster);
            } else {
                System.out.printf("The signature \"%s\" is not valid.\n", sigMaster);
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
