/**
 * This file implements the following functionalities:
 * * generation of a single One Pass Signature (tag=4).
 * * generation of a "double* One Pass Signature (tag=4).
 * * generation of a Detached Signature (tag=2).
 * * verification of a single One Pass Signature (tag=4).
 * * verification of a Detached Signature (tag=2).
 */

package com.beurive;

import java.io.*;
import java.security.Security;

import java.util.Date;
import java.util.Iterator;

import org.beurive.pgp.Document;
import org.beurive.pgp.UnexpectedDocumentException;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.beurive.pgp.Keyring;
import org.beurive.pgp.Stream;


public class Main {

        static Date now = new Date();

        /**
         * Create a single One Pass Signature (tag=4) by signing a document with a given secret key.
         *
         * The structure of the generated document is:
         *
         * ┌───────────────────────────────────┐
         * │ One Pass Signature Packet (tag=4) │
         * └───────────────────────────────────┘
         * ┌───────────────────────────────────┐
         * │ Literal Data Packet (tag=11)      │
         * └───────────────────────────────────┘
         * ┌───────────────────────────────────┐
         * │ Signature Packet (tag=2)          │
         * └───────────────────────────────────┘
         *
         * See https://tools.ietf.org/html/rfc4880#section-5.4:
         *
         *      The One-Pass Signature packet precedes the signed data and contains
         *      enough information to allow the receiver to begin calculating any
         *      hashes needed to verify the signature. It allows the Signature
         *      packet to be placed at the end of the message, so that the signer
         *      can compute the entire signed message in one pass.
         *
         * The One Pass Signature packet contains the following data:
         *      - the signature type.
         *      - the hash algorithm used.
         *      - the public-key algorithm used.
         *      - the Key ID of the signing key.
         *      - a flag showing whether the signature is nested.
         *
         * Please note that the One Pass Signature packet object does **NOT**
         * contain the actual signature, nor the document that has been signed.
         * The document that is being signed is contained into the Literal Data Packet
         * (tag=11). The signature is contained into the Signature Packet (tag=2).
         *
         * @param inDocumentToSign A string that represents the content of the document to sign.
         * @param inOutputFilePath The path to the signature file.
         * @param inKeyRingPath The path to the secret keyring.
         * @param inSecretKeyId The ID of the secret key to use.
         * If the given value is 0, then the master key is used.
         * @param inPassPhrase The passphrase used to activate the secret key.
         * @throws IOException
         * @throws PGPException
         * @throws UnexpectedDocumentException
         */

    static public void singleOnePassSign(String inDocumentToSign,
                                         String inOutputFilePath,
                                         String inKeyRingPath,
                                         long inSecretKeyId,
                                         String inPassPhrase) throws IOException, PGPException, UnexpectedDocumentException {

        byte[] messageCharArray = inDocumentToSign.getBytes();

        // ----------------------------------------------------------------------------------
        // Load the private key and the master public key.
        // ----------------------------------------------------------------------------------

        PGPSecretKeyRing secretKeyRing = Keyring.loadSecretKeyring(inKeyRingPath);
        PGPPrivateKey privateKey;
        PGPPublicKey publicKey;
        if (0 == inSecretKeyId) {
            privateKey = Keyring.getMasterPrivateKey(secretKeyRing, inPassPhrase);
            publicKey = secretKeyRing.getPublicKey();
        } else {
            privateKey = Keyring.getPrivateKeyById(secretKeyRing, inSecretKeyId, inPassPhrase);
            if (null == privateKey) {
                System.out.printf("ERROR: no secret key with ID %X exists, or this key cannot be used for signing!\n", inSecretKeyId);
                System.exit(1);
            }
            publicKey = secretKeyRing.getPublicKey(inSecretKeyId);
        }

        // ----------------------------------------------------------------------------------
        // Create a signature generator.
        // ----------------------------------------------------------------------------------

        int keyAlgorithm = privateKey.getPublicKeyPacket().getAlgorithm();
        int hashAlgorithm = PGPUtil.SHA256;
        PGPSignatureGenerator signerGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm).setProvider("BC")
        );
        // Note about "PGPSignature.BINARY_DOCUMENT".
        //
        // See https://tools.ietf.org/html/rfc4880#section-5.2.1
        //
        // 0x00: Signature of a binary document.
        //       This means the signer owns it, created it, or certifies that it
        //       has not been modified.
        signerGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        // Please note that a Transferable Public Key can have more than one associated user ID.
        // See https://tools.ietf.org/html/rfc4880#section-11.1
        Iterator<String> it = publicKey.getUserIDs();
        while (it.hasNext()) {
            String userId = it.next();
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, userId);
            signerGenerator.setHashedSubpackets(spGen.generate());
        }

        // ----------------------------------------------------------------------------------
        // Create the output stream to the output file.
        // ----------------------------------------------------------------------------------

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

        PGPCompressedDataGenerator compressDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
        ArmoredOutputStream armoredOutputStream = Stream.getBufferedArmoredOutputStreamToFile(inOutputFilePath);
        BCPGOutputStream basicOut = new BCPGOutputStream(compressDataGenerator.open(armoredOutputStream));

        // ----------------------------------------------------------------------------------
        // Create the One Pass Signature Packet.
        //
        // Please note that this packet does not contain the document being signed.
        // It contains data needed to verify the signature against the document:
        //    - the signature type.
        //    - the hash algorithm used.
        //    - the public-key algorithm used.
        //    - the Key ID of the signing key.
        //    - a flag showing whether the signature is nested.
        // ----------------------------------------------------------------------------------

        PGPOnePassSignature onePassSignaturePacket = signerGenerator.generateOnePassVersion(false);
        onePassSignaturePacket.encode(basicOut);

        // ┌───────────────────────────────────┐
        // │ One Pass Signature Packet (tag=4) │ >> basicOut
        // └───────────────────────────────────┘
        // Stream content:
        // ┌───────────────────────────────────┐
        // │ One Pass Signature Packet (tag=4) │
        // └───────────────────────────────────┘

        // ----------------------------------------------------------------------------------
        // Create the Literal Data Packet (tag=11)
        //
        // Please note that thus packet contains the document being signed.
        //
        // A Literal Data packet contains the body of a message; data that is not to be
        // further interpreted.
        //
        // see https://tools.ietf.org/html/rfc4880#section-5.9
        // ----------------------------------------------------------------------------------

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
                now);                    // the time of last modification we want stored.
        lOut.write(messageCharArray);

        // ┌───────────────────────────────────┐
        // │ Literal Data Packet (tag=11)      │ >> basicOut
        // └───────────────────────────────────┘
        // Stream content:
        // ┌───────────────────────────────────┐
        // │ One Pass Signature Packet (tag=4) │
        // └───────────────────────────────────┘
        // ┌───────────────────────────────────┐
        // │ Literal Data Packet (tag=11)      │
        // └───────────────────────────────────┘

        lGen.close();

        // Please see the documentation for the method:
        // org.bouncycastle.openpgp.PGPLiteralDataGenerator.open(java.io.OutputStream, char, java.lang.String, long, java.util.Date)
        //
        // You see that:
        //
        //    The stream created can be closed off by either calling close() on the stream or close() on
        //    the generator. Closing the returned stream does not close off the OutputStream parameter out.
        //
        // Therefore, "lGen.close()" result is:
        //    - "lGen" is closed.
        //    - the stream "lOut" is closed.
        //    - the stream "basicOut" is **NOT** closed.

        // ----------------------------------------------------------------------------------
        // Create the Signature Packet (tag=2).
        // ----------------------------------------------------------------------------------

        signerGenerator.update(messageCharArray);
        signerGenerator.generate().encode(basicOut);

        // ┌───────────────────────────────────┐
        // │ Signature Packet (tag=2)          │ >> basicOut
        // └───────────────────────────────────┘
        // Stream content:
        // ┌───────────────────────────────────┐
        // │ One Pass Signature Packet (tag=4) │
        // └───────────────────────────────────┘
        // ┌───────────────────────────────────┐
        // │ Literal Data Packet (tag=11)      │
        // └───────────────────────────────────┘
        // ┌───────────────────────────────────┐
        // │ Signature Packet (tag=2)          │
        // └───────────────────────────────────┘

        compressDataGenerator.close();
        armoredOutputStream.close();
    }

    /**
     * Generate the data that make a One Pass Signature document:
     * * a One Pass Signature Packet (tag=4)
     * * a Signature Packet (tag=2)
     * @param inDocumentToSign The input stream to the document to sign.
     * @param inSecretKeyRing The secret keyring that contains the secret key to use.
     * @param inKeyId The ID of the signing key to use.
     * @param inPassPhrase The passphrase that protects the private key.
     * @return The method returns an instance of OnePassSignatureData.
     * @throws IOException
     * @throws PGPException
     * @throws UnexpectedKeyException
     */

    static private OnePassSignatureData generateSingleOnePassSignData(
            byte[] inDocumentToSign,
            PGPSecretKeyRing inSecretKeyRing,
            long inKeyId,
            String inPassPhrase) throws IOException, PGPException, UnexpectedKeyException {

        // ----------------------------------------------------------------------------------
        // Extract the necessary data from the secret keyring.
        // ----------------------------------------------------------------------------------

        PGPSecretKey secretKey = inSecretKeyRing.getSecretKey(inKeyId);
        if (null == secretKey) {
            throw new UnexpectedKeyException(String.format("Cannot find any key which ID is %X", inKeyId));
        }
        PGPPublicKey publicKey = secretKey.getPublicKey();
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(inPassPhrase.toCharArray()));

        // ----------------------------------------------------------------------------------
        // Create a signature generator.
        // ----------------------------------------------------------------------------------

        int keyAlgorithm = privateKey.getPublicKeyPacket().getAlgorithm();
        int hashAlgorithm = PGPUtil.SHA256;
        PGPSignatureGenerator signerGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm).setProvider("BC")
        );
        // Note about "PGPSignature.BINARY_DOCUMENT".
        //
        // See https://tools.ietf.org/html/rfc4880#section-5.2.1
        //
        // 0x00: Signature of a binary document.
        //       This means the signer owns it, created it, or certifies that it
        //       has not been modified.
        signerGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        // Please note that a Transferable Public Key can have more than one associated user ID.
        // See https://tools.ietf.org/html/rfc4880#section-11.1
        Iterator<String> it = publicKey.getUserIDs();
        while (it.hasNext()) {
            String userId = it.next();
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, userId);
            signerGenerator.setHashedSubpackets(spGen.generate());
        }

        // ----------------------------------------------------------------------------------
        // Create the One Pass Signature Packet.
        // ----------------------------------------------------------------------------------

        PGPOnePassSignature onePassSignaturePacket = signerGenerator.generateOnePassVersion(false);
        signerGenerator.update(inDocumentToSign);

        return new OnePassSignatureData(onePassSignaturePacket, signerGenerator);
    }

    /**
     * Add a One Pass Signature to a given One Pass Signature document.
     *
     * For example, let's consider the following One Pass Signature document:
     *
     * ┌─────────────────────────────────────┐
     * │ One Pass Signature Packet A (tag=4) │
     * └─────────────────────────────────────┘
     * ┌─────────────────────────────────────┐
     * │ Literal Data Packet (tag=11)        │
     * └─────────────────────────────────────┘
     * ┌─────────────────────────────────────┐
     * │ Signature Packet A (tag=2)          │
     * └─────────────────────────────────────┘
     *
     * Please note that it is possible to add a One Pass Signature Packet to an existing
     * document that contains more than one One Pass Signature Packet.
     *
     * After calling this method, you generate a new document with the following structure:
     *
     * ┌─────────────────────────────────────┐
     * │ One Pass Signature Packet A (tag=4) │
     * └─────────────────────────────────────┘
     * ┌─────────────────────────────────────┐
     * │ One Pass Signature Packet B (tag=4) │
     * └─────────────────────────────────────┘
     * ┌─────────────────────────────────────┐
     * │ Literal Data Packet (tag=11)        │
     * └─────────────────────────────────────┘
     * ┌─────────────────────────────────────┐
     * │ Signature Packet B (tag=2)          │
     * └─────────────────────────────────────┘
     * ┌─────────────────────────────────────┐
     * │ Signature Packet A (tag=2)          │
     * └─────────────────────────────────────┘
     *
     * See https://tools.ietf.org/html/rfc4880#section-5.4
     *
     *      Note that if a message contains more than one one-pass signature,
     *      then the Signature packets bracket the message; that is, the first
     *      Signature packet after the message corresponds to the last one-pass
     *      packet and the final Signature packet corresponds to the first
     *      one-pass packet.
     *
     * @param inSignatureDocument The One Pass Signature document.
     * @param inSecretKeyRing The secret keyring to use.
     * @param inKeyId The ID if the to use.
     * @param inPassPhrase The password that protects the private key to used.
     * @return The method returns an ByteArrayOutputStream that contains the
     * new One Pass Signature document.
     * @throws PGPException
     * @throws IOException
     * @throws UnexpectedKeyException
     */

    public static ByteArrayOutputStream OnePassSignatureReSign(
            BufferedInputStream inSignatureDocument,
            PGPSecretKeyRing inSecretKeyRing,
            long inKeyId,
            String inPassPhrase
    ) throws PGPException, IOException, UnexpectedKeyException {

        // ----------------------------------------------------------------------------------
        // Create a stream reader for PGP objects.
        // ----------------------------------------------------------------------------------

        JcaPGPObjectFactory pgpFact = Document.getObjectFactory(inSignatureDocument);

        // ----------------------------------------------------------------------------------
        // Load the first One Pass Signature.
        // ----------------------------------------------------------------------------------

        PGPOnePassSignatureList sigList = (PGPOnePassSignatureList)pgpFact.nextObject();

        // ----------------------------------------------------------------------------------
        // Load the second packet, which is the Literal Data Packet (tag=11).
        // Please note that a PGPLiteralData object cannot be encoded directly within an
        // output stream.
        // ----------------------------------------------------------------------------------

        PGPLiteralData literalData = (PGPLiteralData)pgpFact.nextObject();
        InputStream literalDataStream = literalData.getInputStream();
        byte[] document = literalDataStream.readAllBytes();

        // ----------------------------------------------------------------------------------
        // Load the third packet, which is the Signature Packet (tag=2).
        // ----------------------------------------------------------------------------------

        PGPSignatureList signatureList = (PGPSignatureList)pgpFact.nextObject();

        // ----------------------------------------------------------------------------------
        // Generate the new Open Pass Signature Packet (tag=4) and the new Signature
        // Packet (tag=2).
        // ----------------------------------------------------------------------------------

        OnePassSignatureData newPackets = generateSingleOnePassSignData(
                document,
                inSecretKeyRing,
                inKeyId,
                inPassPhrase);

        // ----------------------------------------------------------------------------------
        // We have all the objects required to generate the new signature document:
        // * The list of One Pass Signature Packets (tag=4) found in the original signature
        //   document.
        // * The content of the document that has been signed.
        // * The list of Signature Packets (tag=2) found in the original signature document.
        // ----------------------------------------------------------------------------------

        PGPCompressedDataGenerator compressDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        BCPGOutputStream basicOut = new BCPGOutputStream(compressDataGenerator.open(outputStream));

        // ----------------------------------------------------------------------------------
        // Write the existing One Pass Signature Packet (tag=4)
        // ----------------------------------------------------------------------------------

        Iterator<PGPOnePassSignature> onePassSigIt = sigList.iterator();
        while(onePassSigIt.hasNext()) {
            onePassSigIt.next().encode(basicOut);
        }

        // Result:
        // ┌─────────────────────────────────────┐
        // │ One Pass Signature Packet A (tag=4) │
        // └─────────────────────────────────────┘

        // ----------------------------------------------------------------------------------
        // Write the new One Pass Signature Packet (tag=4)
        // ----------------------------------------------------------------------------------

        newPackets.getOnePassSignaturePacket().encode(basicOut);

        // Result:
        // ┌─────────────────────────────────────┐
        // │ One Pass Signature Packet A (tag=4) │
        // └─────────────────────────────────────┘
        // ┌─────────────────────────────────────┐
        // │ One Pass Signature Packet B (tag=4) │
        // └─────────────────────────────────────┘

        // ----------------------------------------------------------------------------------
        // Write the Literal Data Packet (tag=11)
        // ----------------------------------------------------------------------------------

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(
                basicOut,                // the underlying output stream to write the literal data packet to.
                PGPLiteralData.BINARY,   // the format of the literal data that will be written to the output stream.
                PGPLiteralData.CONSOLE,  // the name of the "file" to encode in the literal data object.
                // The special name indicating a "for your eyes only" packet.
                document.length, // the length of the data that will be written.
                now);            // the time of last modification we want stored.
        lOut.write(document);
        lGen.close();

        // Result:
        // ┌─────────────────────────────────────┐
        // │ One Pass Signature Packet A (tag=4) │
        // └─────────────────────────────────────┘
        // ┌─────────────────────────────────────┐
        // │ One Pass Signature Packet B (tag=4) │
        // └─────────────────────────────────────┘
        // ┌─────────────────────────────────────┐
        // │ Literal Data Packet (tag=11)        │
        // └─────────────────────────────────────┘

        // ----------------------------------------------------------------------------------
        // Write the new Signature Packets (tag=2).
        // ----------------------------------------------------------------------------------

        newPackets.getSignerGenerator().generate().encode(basicOut);

        // Result:
        // ┌─────────────────────────────────────┐
        // │ One Pass Signature Packet A (tag=4) │
        // └─────────────────────────────────────┘
        // ┌─────────────────────────────────────┐
        // │ One Pass Signature Packet B (tag=4) │
        // └─────────────────────────────────────┘
        // ┌─────────────────────────────────────┐
        // │ Literal Data Packet (tag=11)        │
        // └─────────────────────────────────────┘
        // ┌─────────────────────────────────────┐
        // │ Signature Packet B (tag=2)          │
        // └─────────────────────────────────────┘

        // Write the existing Signature Packets
        Iterator<PGPSignature> signatureIterator = signatureList.iterator();
        while (signatureIterator.hasNext()) {
            signatureIterator.next().encode(basicOut);
        }

        // Result:
        // ┌─────────────────────────────────────┐
        // │ One Pass Signature Packet A (tag=4) │
        // └─────────────────────────────────────┘
        // ┌─────────────────────────────────────┐
        // │ One Pass Signature Packet B (tag=4) │
        // └─────────────────────────────────────┘
        // ┌─────────────────────────────────────┐
        // │ Literal Data Packet (tag=11)        │
        // └─────────────────────────────────────┘
        // ┌─────────────────────────────────────┐
        // │ Signature Packet B (tag=2)          │
        // └─────────────────────────────────────┘
        // ┌─────────────────────────────────────┐
        // │ Signature Packet A (tag=2)          │
        // └─────────────────────────────────────┘

        compressDataGenerator.close();
        return outputStream;
    }

    /**
     * Generate a detached signature.
     *
     * The structure of the generated document is:
     *
     * ┌───────────────────────────────────┐
     * │ Signature Packet (tag=2)          │
     * └───────────────────────────────────┘
     *
     * See https://tools.ietf.org/html/rfc4880#section-11.4
     *
     *      Some OpenPGP applications use so-called "detached signatures".  For
     *      example, a program bundle may contain a file, and with it a second
     *      file that is a detached signature of the first file.  These detached
     *      signatures are simply a Signature packet stored separately from the
     *      data for which they are a signature.
     *
     * @param inInputFilePath Path to the file from which a signature will be generated.
     * @param inOutputFilePath Path to the output file.
     * @param inKeyRingPath Path to the secret key.
     * @param inSecretKeyId The ID of the secret key to use.
     * If the given value is 0, then the master key is used.
     * @param inPassPhrase Passphrase required for the secret key.
     * @throws IOException
     * @throws PGPException
     * @throws UnexpectedDocumentException
     */

    static public void detachSign(String inInputFilePath,
                                  String inOutputFilePath,
                                  String inKeyRingPath,
                                  long inSecretKeyId,
                                  String inPassPhrase)
            throws IOException, PGPException, UnexpectedDocumentException {

        FileInputStream input = new FileInputStream(inInputFilePath);
        byte[] messageCharArray = input.readAllBytes();

        // ----------------------------------------------------------------------------------
        // Load the private key and the master public key.
        // ----------------------------------------------------------------------------------

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

        // ----------------------------------------------------------------------------------
        // Create a signature generator.
        // ----------------------------------------------------------------------------------

        int keyAlgorithm = privateKey.getPublicKeyPacket().getAlgorithm();
        int hashAlgorithm = PGPUtil.SHA256;
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm).setProvider("BC")
        );

        // Note about "PGPSignature.BINARY_DOCUMENT".
        //
        // See https://tools.ietf.org/html/rfc4880#section-5.2.1
        //
        // 0x00: Signature of a binary document.
        //       This means the signer owns it, created it, or certifies that it
        //       has not been modified.
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        Iterator<String> it = secretKeyRing.getPublicKey().getUserIDs();
        while (it.hasNext()) {
            String userId = it.next();
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, userId);
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }

        // ----------------------------------------------------------------------------------
        // Create the output stream to the output file.
        // ----------------------------------------------------------------------------------

        ArmoredOutputStream armoredOutputStream = Stream.getBufferedArmoredOutputStreamToFile(inOutputFilePath);
        BCPGOutputStream basicOut = new BCPGOutputStream(armoredOutputStream);

        // ----------------------------------------------------------------------------------
        // Create the signature.
        // ----------------------------------------------------------------------------------

        signatureGenerator.update(messageCharArray);
        signatureGenerator.generate().encode(basicOut);

        // ┌───────────────────────────────────┐
        // │ Signature Packet (tag=2)          │ >> basicOut
        // └───────────────────────────────────┘
        // Stream content:
        // ┌───────────────────────────────────┐
        // │ Signature Packet (tag=2)          │
        // └───────────────────────────────────┘

        armoredOutputStream.close();
    }

    /**
     * Verify a given single One Pass Signature.
     *
     * The structure of the signature being verified is:
     *
     * ┌───────────────────────────────────┐
     * │ One Pass Signature Packet (tag=4) │
     * └───────────────────────────────────┘
     * ┌───────────────────────────────────┐
     * │ Literal Data Packet (tag=11)      │
     * └───────────────────────────────────┘
     * ┌───────────────────────────────────┐
     * │ Signature Packet (tag=2)          │
     * └───────────────────────────────────┘
     *
     * See https://tools.ietf.org/html/rfc4880#section-5.4:
     *
     *      The One-Pass Signature packet precedes the signed data and contains
     *      enough information to allow the receiver to begin calculating any
     *      hashes needed to verify the signature. It allows the Signature
     *      packet to be placed at the end of the message, so that the signer
     *      can compute the entire signed message in one pass.
     *
     * The One Pass Signature packet contains the following data:
     *      - the signature type.
     *      - the hash algorithm used.
     *      - the public-key algorithm used.
     *      - the Key ID of the signing key.
     *      - a flag showing whether the signature is nested.
     *
     * Please note that the One Pass Signature Packet object does **NOT**
     * contain the actual signature, nor the document that has been signed.
     * It contains date need to verify the signature.
     *
     * @param inSignatureFilePath
     * @param pubKeyRing
     * @return
     * @throws Exception
     */

    private static boolean verifySingleOnePassSig(
            String inSignatureFilePath,
            PGPPublicKeyRing pubKeyRing)
            throws Exception
    {
        // ----------------------------------------------------------------------------------
        // Create a stream reader for PGP objects.
        // ----------------------------------------------------------------------------------

        JcaPGPObjectFactory pgpFact = Document.getObjectFactory(inSignatureFilePath);

        // ----------------------------------------------------------------------------------
        // Load the first packet, which is the One Pass Signature Packet (tag=4).
        //
        // Please note that a signature document may contain more than one
        // One Pass Signature Packet. However, in this particular use case, the provided
        // signature document only contains a single One Pass Signature Packet.
        //
        // See https://tools.ietf.org/html/rfc4880#section-5.4
        // ----------------------------------------------------------------------------------

        PGPOnePassSignatureList sigList = (PGPOnePassSignatureList)pgpFact.nextObject();
        PGPOnePassSignature onePassSignature = sigList.get(0);
        PGPPublicKey publicKey = pubKeyRing.getPublicKey(onePassSignature.getKeyID());
        onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);

        // ----------------------------------------------------------------------------------
        // Load the second packet, which is the Literal Data Packet (tag=11).
        // ----------------------------------------------------------------------------------

        PGPLiteralData literalData = (PGPLiteralData)pgpFact.nextObject();

        // ----------------------------------------------------------------------------------
        // Get an input stream on the literal data being stored in the Literal Data Packet.
        // ----------------------------------------------------------------------------------

        InputStream literalDataStream = literalData.getInputStream();

        // ----------------------------------------------------------------------------------
        // - Open an output stream to the output file.
        // - Write the literal data (that is, the original file that has been signed) into
        //   the output file.
        // - Inject the content of the literal data packet (that is, the original file that
        //   has been signed) into the PGPOnePassSignature so that it can verify the
        //   signature against it.
        // ----------------------------------------------------------------------------------

        FileOutputStream out = new FileOutputStream(literalData.getFileName());
        int ch;
        // Please note that we proceed byte per byte to show that it is possible to do so
        // (in case we need to manipulate very big documents).
        while ((ch = literalDataStream.read()) >= 0)
        {
            // We create the file that was originally signed.
            out.write(ch);
            // Push the signed document into the PGPOnePassSignature object.
            // This data is necessary in order to verify the signature.
            onePassSignature.update((byte)ch);
        }

        out.close(); // Close the file that was originally signed.

        // ----------------------------------------------------------------------------------
        // Signature Packet (tag=2)
        //
        // Please note that a signature document may have more than one Signature Packet.
        //
        // See https://tools.ietf.org/html/rfc4880#section-5.4
        // ----------------------------------------------------------------------------------

        PGPSignatureList signaturePacketList = (PGPSignatureList)pgpFact.nextObject();
        PGPSignature signaturePacket = signaturePacketList.get(0);

        // ----------------------------------------------------------------------------------
        // Inject the signature packet into the PGPOnePassSignature object.
        //
        // Now, the PGPOnePassSignature object has everything it needs to
        // verify the signature:
        //     - the signature type.
        //     - the hash algorithm used.
        //     - the public-key algorithm used.
        //     - the Key ID of the signing key.
        //     - a flag showing whether the signature is nested.
        //     - the document that has been signed.
        //     - the signature.
        // We can proceed to the verification.
        // ----------------------------------------------------------------------------------

        return onePassSignature.verify(signaturePacket);
    }

    /**
     * Verify a given detached signature.
     *
     * The structure of the signature being verified is:
     *
     * ┌───────────────────────────────────┐
     * │ Signature Packet (tag=2)          │
     * └───────────────────────────────────┘
     *
     * See https://tools.ietf.org/html/rfc4880#section-11.4
     *
     *      Some OpenPGP applications use so-called "detached signatures".  For
     *      example, a program bundle may contain a file, and with it a second
     *      file that is a detached signature of the first file.  These detached
     *      signatures are simply a Signature packet stored separately from the
     *      data for which they are a signature.
     *
     * @param inSignatureFile Path to the file that contains the signature.
     * @param pubKeyRing The public keyring.
     * @return If the signature is valid, then the method returns the value true.
     * Otherwise, it returns the value false.
     * @throws Exception
     */

    private static boolean verifyDetachedSig(
            String inDocument,
            String inSignatureFile,
            PGPPublicKeyRing pubKeyRing)
            throws Exception
    {
        // ----------------------------------------------------------------------------------
        // Load the document that has been signed.
        // ----------------------------------------------------------------------------------

        FileInputStream documentStream = new FileInputStream(new File(inDocument));
        byte[] document = documentStream.readAllBytes();

        // ----------------------------------------------------------------------------------
        // Create a stream reader for PGP objects.
        // ----------------------------------------------------------------------------------

        JcaPGPObjectFactory pgpFact = Document.getObjectFactory(inSignatureFile);

        // ----------------------------------------------------------------------------------
        // Load the first packet, which is a Signature Packet (tag=2).
        // ----------------------------------------------------------------------------------

        PGPSignatureList signatureList = (PGPSignatureList) pgpFact.nextObject();
        PGPSignature signature = signatureList.get(0);

        // ----------------------------------------------------------------------------------
        // Configure the PGPSignature object so it can be used to verify the signature.
        // In order to verify the
        // ----------------------------------------------------------------------------------

        PGPPublicKey publicKey = pubKeyRing.getPublicKey(signature.getKeyID());
        signature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
        signature.update(document);

        return signature.verify();
    }

    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());
        final String documentToSign = "Message to sign";
        final String passPhrase = "password";
        final String secretKeyRingPath = "./data/secret-keyring.pgp";
        final String publicKeyRingPath = "./data/public-keyring.pgp";
        final String fileToSignPath = "./data/document-to-sign.txt";
        final String sigMasterPath = "./data/signature-master.pgp";
        final String sigSubKeyPath = "./data/signature-subkey.pgp";
        final String sigSubKeyPathBis = "./data/signature-subkey-bis.pgp";
        final String sigDetachedMasterPath = "./data/detached-signature-master.pgp";
        final String sigDetachedSubKeyPath = "./data/detached-signature-subkey.pgp";
        final String reSigDocumentPath = "./data/resig-signature-master.pgp";

        try {
            // Print the list of key IDs in the secret key ring.
            System.out.printf("List of key IDs in the key ring \"%s\":\n", secretKeyRingPath);
            PGPSecretKey[] keys = Keyring.getSecretKeys(Keyring.loadSecretKeyring(secretKeyRingPath), false);
            for (PGPSecretKey k: keys) {
                System.out.printf("\t- %016X (sign ? %s, master ? %s)\n",
                        k.getKeyID(),
                        k.isSigningKey() ? "yes" : "no",
                        k.isMasterKey() ? "yes" : "no");
            }

            // Sign with the master key.
            System.out.printf("Sign <%s> using the master key => \"%s\".\n", documentToSign, sigMasterPath);
            singleOnePassSign(documentToSign,
                    sigMasterPath,
                    secretKeyRingPath,
                    0,
                    passPhrase);

            // Sign with a subkey.
            System.out.printf("Sign <%s> using a sub key [%X] => \"%s\".\n", documentToSign, keys[1].getKeyID(), sigSubKeyPath);
            singleOnePassSign(documentToSign,
                    sigSubKeyPath,
                    secretKeyRingPath,
                    keys[1].getKeyID(),
                    passPhrase);

            // Sign with a subkey again.
            // So we can compare the 2 files.
            System.out.printf("Sign <%s> using a sub key [%X] => \"%s\".\n", documentToSign, keys[1].getKeyID(), sigSubKeyPathBis);
            singleOnePassSign(documentToSign,
                    sigSubKeyPathBis,
                    secretKeyRingPath,
                    keys[1].getKeyID(),
                    passPhrase);

            // Detach sign with the master key.
            System.out.printf("Detach sign <%s> using the master key => \"%s\".\n", fileToSignPath, sigDetachedMasterPath);
            detachSign(fileToSignPath,
                    sigDetachedMasterPath,
                    secretKeyRingPath,
                    0,
                    passPhrase);

            // Detach sign with a sub key.
            System.out.printf("Detach sign <%s> using the sub key [%X] => \"%s\".\n", fileToSignPath, keys[1].getKeyID(), sigDetachedSubKeyPath);
            detachSign(fileToSignPath,
                    sigDetachedSubKeyPath,
                    secretKeyRingPath,
                    keys[1].getKeyID(),
                    passPhrase);

            // Add the One Pass Signature to an existing One Pass Signature document.
            BufferedInputStream document = new BufferedInputStream(new FileInputStream(new File(sigMasterPath)));
            PGPSecretKeyRing secretKeyRing = Keyring.loadSecretKeyring(secretKeyRingPath);
            PGPSecretKey[] secretSigningKeys = Keyring.getSecretKeys(secretKeyRing, true);
            PGPSecretKey resigningSecretKey = secretSigningKeys[0];
            System.out.printf("Re-sign <%s> using the sub key [%X] => \"%s\".\n",
                    fileToSignPath,
                    resigningSecretKey.getKeyID(),
                    reSigDocumentPath);
            ByteArrayOutputStream newDoc = OnePassSignatureReSign(
                    document,
                    secretKeyRing,
                    secretSigningKeys[1].getKeyID(),
                    passPhrase);
            FileOutputStream outFile = new FileOutputStream(new File(reSigDocumentPath));
            outFile.write(newDoc.toByteArray());

            // Verify the One Pass Signatures.
            PGPPublicKeyRing pubKeyRing = Keyring.loadPublicKeyring(publicKeyRingPath);

            if (verifySingleOnePassSig(sigMasterPath, pubKeyRing)) {
                System.out.printf("The signature \"%s\" is valid.\n", sigMasterPath);
            } else {
                System.out.printf("The signature \"%s\" is not valid.\n", sigMasterPath);
            }

            if (verifySingleOnePassSig(sigSubKeyPath, pubKeyRing)) {
                System.out.printf("The signature \"%s\" is valid.\n", sigSubKeyPath);
            } else {
                System.out.printf("The signature \"%s\" is not valid.\n", sigSubKeyPath);
            }

            // Verify the detached signatures.
            if (verifyDetachedSig(fileToSignPath, sigDetachedMasterPath, pubKeyRing)) {
                System.out.printf("The signature \"%s\" is valid.\n", sigDetachedMasterPath);
            } else {
                System.out.printf("The signature \"%s\" is not valid.\n", sigDetachedMasterPath);
            }

            if (verifyDetachedSig(fileToSignPath, sigDetachedMasterPath, pubKeyRing)) {
                System.out.printf("The signature \"%s\" is valid.\n", sigDetachedSubKeyPath);
            } else {
                System.out.printf("The signature \"%s\" is not valid.\n", sigDetachedSubKeyPath);
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
