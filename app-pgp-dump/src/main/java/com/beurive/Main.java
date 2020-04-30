package com.beurive;

import java.io.*;
import java.security.Security;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
     * Load a public key ring from a given file.
     * @param inPath Path to the secret key ring.
     * @return The secret key ring.
     * @throws IOException
     * @throws NullPointerException
     */

    private static PGPPublicKeyRing loadPublicKeyRing(String inPath)
            throws IOException, NullPointerException {
        // Load the secret key ring.
        ArmoredInputStream inputStream = getArmoredInputStream(inPath);
        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(
                inputStream, new JcaKeyFingerprintCalculator());

        Object pgpObject;
        PGPPublicKeyRing publicKeyRing = null;
        while ((pgpObject = pgpObjectFactory.nextObject()) != null) {
            publicKeyRing = (PGPPublicKeyRing)pgpObject;
        }
        inputStream.close();
        return publicKeyRing;
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
     * @param inDocumentToSign A string that represents the content of the document to sign.
     * @param inOutputFilePath The path to the signature file.
     * @param inKeyRingPath The path to the secret key ring.
     * @param inSecretKeyId The ID of the secret key to use.
     * If the given value is 0, then the master key is used.
     * @param inPassPhrase The passphrase used to activate the secret key.
     * @param inDoCompress Tells whether the signature must be compressed or not.
     * This value true means that the signature must be compressed.
     * @throws IOException
     * @throws PGPException
     */

    static public void sign(String inDocumentToSign,
                            String inOutputFilePath,
                            String inKeyRingPath,
                            long inSecretKeyId,
                            String inPassPhrase,
                            boolean inDoCompress) throws IOException, PGPException {

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
            spGen.setSignerUserID(false, userId);
            signerGenerator.setHashedSubpackets(spGen.generate());
        }

        // Create the Basic output stream.
        BCPGOutputStream basicOut;
        PGPCompressedDataGenerator compressDataGenerator = null;
        ArmoredOutputStream armoredOutputStream = getArmoredOutputStream(inOutputFilePath);
        if (inDoCompress) {
            compressDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
            basicOut = new BCPGOutputStream(compressDataGenerator.open(armoredOutputStream));
        } else {
            basicOut = new BCPGOutputStream(armoredOutputStream);
        }

        PGPOnePassSignature signature = signerGenerator.generateOnePassVersion(false);
        signature.encode(basicOut); // => write the OnePassSignaturePacket (tag=4)

        // PGPLiteralDataGenerator: Generator for producing literal data packets.
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(
                basicOut,                // the underlying output stream to write the literal data packet to.
                PGPLiteralData.BINARY,   // the format of the literal data that will be written to the output stream.
                PGPLiteralData.CONSOLE,  // the name of the "file" to encode in the literal data object.
                                         // The special name indicating a "for your eyes only" packet.
                messageCharArray.length, // the length of the data that will be written.
                new Date());             // the time of last modification we want stored.

        // Write le literal data packet.
        lOut.write(messageCharArray); // Write the LiteralData (tag=11)

        // Inject the data to sign into the generator (but don't generate the signature yet).
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

        // Generate the (fully calculated) signature and send it to "basicOut".
        signerGenerator.generate().encode(basicOut); // Write the SignaturePacket (tag=2)
        if (inDoCompress) {
            compressDataGenerator.close();
        }
        armoredOutputStream.close();
    }

    /**
     * Print the tags of all the packets found within a given PGP document.
     * @param inDocumentPath Path to the PGP document.
     * @param inIsCompressed Flag that tells whether the PGP document contains compressed data or not.
     * The value true means that the PGP document contains compressed data.
     * @throws IOException
     * @throws PGPException
     */

    static private void listPacketTags(String inDocumentPath, boolean inIsCompressed) throws IOException, PGPException {

        ArmoredInputStream armoredinputStream = getArmoredInputStream(inDocumentPath);
        BCPGInputStream pgpObjectsStreamReader; // Stream reader for PGP objects
        if (inIsCompressed) {
            PGPCompressedData data = new PGPCompressedData(armoredinputStream);
            pgpObjectsStreamReader = new BCPGInputStream(data.getDataStream());
        } else {
            pgpObjectsStreamReader = new BCPGInputStream(armoredinputStream);
        }

        System.out.println(String.format("Tags for the PGP document \"%s\":", inDocumentPath));
        int tag, index=1;
        while (((tag = pgpObjectsStreamReader.nextPacketTag()) != -1)) {
            System.out.println(String.format("  - [%d] tag = %d", index++, tag));
            if (pgpObjectsStreamReader.readPacket() == null) break;
        }
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        String documentToSign = "This the document to sign";
        String passPhrase = "password";
        String secretKeyRing = "./data/secret-keyring.pgp";
        String sigMaster = "./data/signature-master.pgp";
        String sigMasterUncompressed = "./data/signature-master-uncompressed.pgp";

        try {
            // Print the list of key IDs in the secret key ring.
            System.out.printf("List of key IDs in the secret key ring \"%s\":\n", secretKeyRing);
            List<PGPSecretKey> keys = getSecretKeyIds(secretKeyRing);
            for (PGPSecretKey k: keys) {
                System.out.printf("\t- %016X (sign ? %s, master ? %s)\n",
                        k.getKeyID(),
                        k.isSigningKey() ? "yes" : "no",
                        k.isMasterKey() ? "yes" : "no");
            }

            // Sign with the master key.
            System.out.printf("Compress-sign <%s> using the master key => \"%s\".\n", documentToSign, sigMaster);
            sign(documentToSign,
                    sigMaster,
                    secretKeyRing,
                    0,
                    passPhrase,
            true);
            listPacketTags(secretKeyRing, false);

            System.out.printf("Uncompress-sign <%s> using the master key => \"%s\".\n", documentToSign, sigMasterUncompressed);
            sign(documentToSign,
                    sigMasterUncompressed,
                    secretKeyRing,
                    0,
                    passPhrase,
                    false);

            listPacketTags(secretKeyRing, false);

            listPacketTags(sigMasterUncompressed, false);
            listPacketTags(sigMaster, true);

        } catch (IOException | PGPException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
