package com.beurive;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.attr.ImageAttribute;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.util.Arrays;

public class Main {

    /**
     * Create a FileOutputStream.
     * @param inPath Path to the file.
     * @return A new FileOutputStream.
     * @throws FileNotFoundException
     */

    static private FileOutputStream getFileOutputStream(String inPath) throws FileNotFoundException {
        return new FileOutputStream(new File(inPath));
    }

    /**
     * Create an RSA key pair.
     * @return An RSA key pair.
     * @throws PGPException
     * @note You should set the strength of the key to at least 1024.
     * @see https://stackoverflow.com/questions/2678138/is-there-a-size-restriction-on-signatures-in-java-java-security
     */

    private static PGPKeyPair createRsaKeyPair() throws PGPException {
        // Create a key pair generator for RSA.
        RSAKeyPairGenerator rsaKpg = new RSAKeyPairGenerator();
        BigInteger publicExponent = BigInteger.valueOf(0x11);
        SecureRandom random = new SecureRandom();
        // **WARNING**: You should set the strength of the key to at least 1024.
        // see https://stackoverflow.com/questions/2678138/is-there-a-size-restriction-on-signatures-in-java-java-security
        int strength = 1024;
        int certainty = 25;
        rsaKpg.init(new RSAKeyGenerationParameters(
                publicExponent,
                random,
                strength,
                certainty));

        // Generate the RSA keys.
        AsymmetricCipherKeyPair rsaKp = rsaKpg.generateKeyPair();
        return new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKp, new Date());
    }

    /**
     * Return a keyring generator.
     * @param inPairs List of PGP key pairs.
     * @param inIdentity Identity of the key owner.
     * @param inPassPhrase Passphrase used to encrypt the secret keys.
     * @return A new keyring generator.
     * @throws IllegalArgumentException
     * @throws PGPException
     */

    private static PGPKeyRingGenerator getKeyRingGenerator(PGPKeyPair[] inPairs,
                                                           String inIdentity,
                                                           String inPassPhrase) throws IllegalArgumentException, PGPException {
        if (0 == inPairs.length) {
            throw new IllegalArgumentException("No key given!");
        }
        char[] passPhrase = inPassPhrase.toCharArray();

        // See RFC 4840: [9.4. Hash Algorithms]
        // https://tools.ietf.org/html/rfc4880#section-9.4
        // Note: only SHA1 supported for key checksum calculations
        // org.bouncycastle.openpgp.PGPException: only SHA1 supported for key checksum calculations.
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA256);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                // See RFC 4880: [5.2.1. Signature Types]
                // https://tools.ietf.org/html/rfc4880#section-5.2.1
                // PGPSignature.POSITIVE_CERTIFICATION,
                PGPSignature.DEFAULT_CERTIFICATION, // 0x10
                inPairs[0],
                inIdentity,
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(inPairs[0].getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc).setProvider("BC").build(passPhrase)
        );

        for (int i=1; i<inPairs.length; i++) {
            keyRingGen.addSubKey(inPairs[i]);
        }
        return keyRingGen;
    }


    /**
     * Illustrates the use of ByteArrayInputStream / ByteArrayOutputStream.
     * @throws IOException
     */

    static private void showByteArrayStreams() throws IOException {

        byte[] data = new byte[]{0, 1, 2, 3};

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (byte b: data) output.write(b);
        byte[] content = output.toByteArray();
        assert content.length == data.length;
        for (int i=0; i<data.length; i++) assert data[i] == content[i];

        ByteArrayInputStream input1 = new ByteArrayInputStream(data);
        List<Byte> readBytes = new ArrayList<>();
        int b;
        while ((b = input1.read()) != -1) readBytes.add((byte)b);
        assert data.length == readBytes.size();

        String filePath = "data/bytes-output";
        output.writeTo(new FileOutputStream(new File(filePath)));

        ByteArrayInputStream input2 = new ByteArrayInputStream(data);
        filePath = "data/bytes-input";
        input2.transferTo(new FileOutputStream(new File(filePath)));
    }

    /**
     * Illustrates the use of ArmoredInputStream / ArmoredOutputStream.
     * @throws IOException
     */

    static private void showArmoredStreams() throws IOException {
        String message = "This is a text";

        ByteArrayOutputStream target = new ByteArrayOutputStream();
        ArmoredOutputStream output = new ArmoredOutputStream(target);
        output.write(message.getBytes());
        output.close();
        String armoredTarget = target.toString();
        System.out.printf("Input:\n\n%s\n\nArmored text:\n\n%s\n",
                message,
                armoredTarget);

        ArmoredInputStream in_stream = new ArmoredInputStream(new ByteArrayInputStream(armoredTarget.getBytes()));
        byte[] content = in_stream.readAllBytes();
        assert message.equals(new String(content));
    }

    /**
     * Illustrates the use of PGPCompressedDataGenerator.
     * @throws IOException
     */

    static private void showCompression() throws IOException {
        String document = "This is the document content";

        // Compress the document.
        PGPCompressedDataGenerator compressor = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        // Return an OutputStream which will save the data being written to the compressed object.
        OutputStream compressedOutputStream = compressor.open(output);
        // The following line of code could be replaced by:
        // for (byte b: document.getBytes()) { compressedOutputStream.write(b); }
        compressedOutputStream.write(document.getBytes());
        compressedOutputStream.close(); // Stream "output" is still opened.
        byte[] compressedDocument = output.toByteArray();
        output.close();

        // Decompress the document.
        PGPCompressedData data = new PGPCompressedData(compressedDocument);
        InputStream input = data.getInputStream();
        String decompressedDocument = new String(input.readAllBytes());
        assert decompressedDocument.equals(document);
    }

    static private String dumpSignatureSubPackets(SignatureSubpacket[] inSps, String inIndent) {
        // No stream
        StringBuilder res = new StringBuilder();
        for (int i=0; i<inSps.length; i++) {
            res.append(String.format("%sSignatureSubpacket:\n", inIndent));
            SignatureSubpacket p = inSps[i];
            res.append(String.format("%s\tType: %d\n", inIndent, p.getType()));
            res.append(String.format("%s\tIs critical: %s\n", inIndent, p.isCritical() ? "yes" : "no"));
            res.append(String.format("%s\tData length: %d\n", inIndent, p.getData().length));
        }
        return res.toString();
    }

    static private String dumpPGPSignature(PGPSignature o, String inIndent) throws PGPException {
        // No stream
        StringBuilder res = new StringBuilder(String.format("%sPGPSignature:\n", inIndent));
        res.append(String.format("%s\tVersion: %d\n", inIndent, o.getVersion()));
        res.append(String.format("%s\tType: %d (%X)\n", inIndent, o.getSignatureType(), o.getSignatureType()));
        res.append(String.format("%s\tCreation time: %s\n", inIndent, o.getCreationTime().toString()));
        res.append(String.format("%s\tHash Algorithm: %d\n", inIndent, o.getHashAlgorithm()));
        res.append(String.format("%s\tKey Algorithm: %d\n", inIndent, o.getKeyAlgorithm()));
        res.append(String.format("%s\tKey ID: %X\n", inIndent, o.getKeyID()));
        res.append(String.format("%s\tIs certification ? %s\n", inIndent, o.isCertification() ? "yes" : "no"));
        res.append(String.format("%s\tHas sub packets ? %s\n", inIndent, o.hasSubpackets() ? "yes" : "no"));
        res.append(String.format("%s\tSignature: %H\n", inIndent, o.getSignature()));

        if (o.hasSubpackets()) {
            res.append(String.format("%s\tHas hashed sub-packet count: %d\n", inIndent, o.getHashedSubPackets().size()));
            res.append(dumpSignatureSubPackets(o.getHashedSubPackets().toArray(), String.format("%s\t\t", inIndent)));
            res.append(String.format("%s\tHas un-hashed sub-packet count: %d\n", inIndent, o.getUnhashedSubPackets().size()));
            res.append(dumpSignatureSubPackets(o.getUnhashedSubPackets().toArray(), String.format("%s\t\t", inIndent)));
        }
        return res.toString();
    }

    static private String dumpPGPSignatureList(PGPSignatureList o, String inIndent) throws PGPException {
        // No stream
        StringBuilder res = new StringBuilder(String.format("%sPGPSignatureList:\n", inIndent));
        res.append(String.format("%s\tNumber of signatures: %d\n", inIndent, o.size()));
        res.append(String.format("%s\tSignatures:\n", inIndent));
        res.append(String.format("%s\tIs empty: %s\n", inIndent, o.isEmpty() ? "yes" : "no"));
        for(PGPSignature s: o) {
            res.append(dumpPGPSignature(s, String.format("%s\t", inIndent)));
        }
        return res.toString();
    }

    static private String dumpImageAttribute(ImageAttribute o, String inIndent) {
        // No stream
        StringBuilder res = new StringBuilder(String.format("%sImageAttribute:\n", inIndent));
        res.append(String.format("%s\tEncoding: %d\n", inIndent, o.getEncoding()));
        res.append(String.format("%s\tImage data length: %d\n", inIndent, o.getImageData().length));
        return res.toString();
    }

    static private String dumpPGPSecretKey(PGPSecretKey o, String inIndent) {
        // No stream
        StringBuilder res = new StringBuilder(String.format("%sPGPSecretKey:\n", inIndent));
        res.append(String.format("%s\tID: %X\n", inIndent, o.getKeyID()));
        res.append(String.format("%s\tIs master ley ? %s\n", inIndent, o.isMasterKey() ? "yes" : "no"));
        res.append(String.format("%s\tIs signing ley ? %s\n", inIndent, o.isSigningKey() ? "yes" : "no"));
        res.append(String.format("%s\tIs empty ? %s\n", inIndent, o.isPrivateKeyEmpty() ? "yes" : "no"));
        res.append(String.format("%s\tEncryption algorithm: %d\n", inIndent, o.getKeyEncryptionAlgorithm()));
        res.append(String.format("%s\tIs private key empty: %s\n", inIndent, o.isPrivateKeyEmpty() ? "yes" : "no"));
        res.append(String.format("%s\tS2K usage: %d\n", inIndent, o.getS2KUsage()));
        Iterator<PGPUserAttributeSubpacketVector> att = o.getUserAttributes();
        while (att.hasNext()) {
            PGPUserAttributeSubpacketVector a = att.next();
            ImageAttribute img = a.getImageAttribute();
            res.append(dumpImageAttribute(img, String.format("%s\t", inIndent)));
        }

        res.append(String.format("%s\tUser IDs:\n", inIndent));
        Iterator<String> id = o.getUserIDs();
        while (id.hasNext()) {
            res.append(String.format("%s\t\tUser ID: %s\n", inIndent, id.next()));
        }

        return res.toString();
    }

    static private String dumpPGPSecretKeyRing(PGPSecretKeyRing o, String inIndent) {
        // No stream
        StringBuilder res = new StringBuilder(String.format("%sPGPSecretKeyRing:\n", inIndent));
        res.append(String.format("%s", res.toString()));
        for(PGPSecretKey s: o) {
            res.append(dumpPGPSecretKey(s, String.format("%s\t", inIndent)));
        }
        return res.toString();
    }

    static private String dumpPGPPublicKey(PGPPublicKey o, String inIndent) throws PGPException {
        // No stream
        StringBuilder res = new StringBuilder(String.format("%sPGPPublicKey:\n", inIndent));
        res.append(String.format("%s\tID: %X\n", inIndent, o.getKeyID()));
        res.append(String.format("%s\tVersion: %d\n", inIndent, o.getVersion()));
        res.append(String.format("%s\tValid seconds: %d\n", inIndent, o.getValidSeconds()));
        res.append(String.format("%s\tAlgorithm: %d\n", inIndent, o.getAlgorithm()));
        res.append(String.format("%s\tBit strength: %d\n", inIndent, o.getBitStrength()));
        res.append(String.format("%s\tBit creation time: %s\n", inIndent, o.getCreationTime().toString()));
        res.append(String.format("%s\tFingerprint: %s\n", inIndent, new String(o.getFingerprint())));
        res.append(String.format("%s\tUser IDs:\n", inIndent));
        Iterator<String> users = o.getUserIDs();
        while(users.hasNext()) {
            res.append(String.format("%s\t\t%s\n", inIndent, users.next()));
        }
        res.append(String.format("%s\tSignatures:\n", inIndent));
        res.append(String.format("%s", res.toString()));
        Iterator<PGPSignature> sigs = o.getSignatures();
        while (sigs.hasNext()) {
            res.append(dumpPGPSignature(sigs.next(), String.format("%s\t", inIndent)));
        }
        return res.toString();
    }

    static private String dumpPGPPublicKeyRing(PGPPublicKeyRing o, String inIndent) throws PGPException {
        // No stream
        StringBuilder res = new StringBuilder(String.format("%sPGPPublicKeyRing:\n", inIndent));
        res.append(String.format("%s\tPublic keys:\n", inIndent));
        res.append(String.format("%s", res.toString()));
        Iterator<PGPPublicKey> keys = o.getPublicKeys();
        while(keys.hasNext()) {
            res.append(dumpPGPPublicKey(keys.next(), String.format("%s\t", inIndent)));
        }
        return res.toString();
    }

    static private String dumpPGPCompressedData(PGPCompressedData o, String inIndent) {
        // Warning: do not consume the input streams returned by one of the following method here:
        //          - o.getDataStream()
        //          - o.getInputStream()
        //          If you do, then the rest of the document will not be parsed.

        StringBuilder res = new StringBuilder(String.format("%sPGPCompressedData:\n", inIndent));
        res.append(String.format("%s\tAlgorithm: %d\n", inIndent, o.getAlgorithm()));
        return res.toString();
    }

    static private String dumpPGPLiteralData(PGPLiteralData o, String inIndent) throws IOException {
        StringBuilder res = new StringBuilder(String.format("%sPGPLiteralData:\n", inIndent));
        res.append(String.format("%s\tFormat: %d (0x%X)\n", inIndent, o.getFormat(), o.getFormat()));
        res.append(String.format("%s\tFile name: %s\n", inIndent, o.getFileName()));
        res.append(String.format("%s\tModification time: %s\n", inIndent, o.getModificationTime().toString()));
        res.append(String.format("%s\tData length: %d\n", inIndent, o.getInputStream().readAllBytes().length));
        return res.toString();
    }

    static private String dumpPGPEncryptedData(PGPEncryptedData o, String inIndent) throws IOException {
        StringBuilder res = new StringBuilder(String.format("%sPGPEncryptedData:\n", inIndent));
        res.append(String.format("%s\tIntegrity protected ? %s\n", inIndent, o.isIntegrityProtected() ? "yes" : "no"));
        res.append(String.format("%s\tData length: %d\n", inIndent, o.getInputStream().readAllBytes().length));
        return res.toString();
    }

    static private String dumpPGPEncryptedDataList(PGPEncryptedDataList o, String inIndent) throws IOException {
        StringBuilder res = new StringBuilder(String.format("%sPGPEncryptedDataList:\n", inIndent));
        Iterator<PGPEncryptedData> data = o.getEncryptedDataObjects();
        res.append(String.format("%s\tEncrypted data list:\n", inIndent));
        res.append(String.format("%s", res.toString()));
        while (data.hasNext()) {
            res.append(dumpPGPEncryptedData(data.next(), String.format("%s\t", inIndent)));
        }
        return res.toString();
    }

    static private String dumpPGPOnePassSignature(PGPOnePassSignature o, String inIndent) throws IOException {
        // No stream
        StringBuilder res = new StringBuilder(String.format("%sPGPOnePassSignature:\n", inIndent));
        res.append(String.format("%s\tKey ID: %X\n", inIndent, o.getKeyID()));
        res.append(String.format("%s\tType: %d:\n", inIndent, o.getSignatureType()));
        res.append(String.format("%s\tHash algorithm: %d:\n", inIndent, o.getHashAlgorithm()));
        res.append(String.format("%s\tKey algorithm: %d:\n", inIndent, o.getKeyAlgorithm()));
        res.append(String.format("%s\tData length: %d:\n", inIndent, o.getEncoded().length));
        return res.toString();
    }

    static private String dumpPGPOnePassSignatureList(PGPOnePassSignatureList o, String inIndent) throws IOException {
        // No stream
        StringBuilder res = new StringBuilder(String.format("%sPGPOnePassSignatureList:\n", inIndent));
        res.append(String.format("%s\tIs empty: %s\n", inIndent, o.isEmpty() ? "yes" : "no"));
        res.append(String.format("%s\tSize: %d\n", inIndent, o.size()));
        Iterator<PGPOnePassSignature> sigs = o.iterator();

        StringBuilder sub = new StringBuilder();
        boolean hasSig = false;
        while (sigs.hasNext()) {
            hasSig = true;
            sub.append(dumpPGPOnePassSignature(sigs.next(), String.format("%s\t\t", inIndent)));
        }
        if (hasSig) {
            res.append(String.format("%s\tPGPOnePassSignature list:\n", inIndent));
            res.append(sub.toString());
        }

        return res.toString();
    }

    static private String dumpPGPMarker(PGPMarker o, String inIndent) {
        // No stream
        return String.format("%sPGPMarker: %s\n", inIndent, o.getClass().getName());
    }

    /**
     * Illustrates the use of BCPGInputStream / JcaPGPObjectFactory.
     * This method "dumps" the structure of a given PGP document identified by its path.
     * @param InPgpDocument Path to the PGP document to "dump".
     * @throws PGPException
     * @throws IOException
     */

    static private void showBCPGInputStream(String InPgpDocument) throws PGPException, IOException {
        // Note:
        //   If the PGP document is "compressed", then it is not "fully" compressed.
        //   The document begins with "0b101000xx" (for old format) or "0b11001000" (for new format).
        //   => it indicated a "Compressed Data Packet" (tag=8 / 0b1000).

        // Stream reader for PGP objects
        BCPGInputStream pgpObjectsReader = null;
        ArmoredInputStream armoredInputStream = new ArmoredInputStream(new FileInputStream(new File(InPgpDocument)));
        pgpObjectsReader = new BCPGInputStream(armoredInputStream);
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpObjectsReader);

        // Dump
        System.out.printf("%s:\n", InPgpDocument);
        List<Object> unexpected = new ArrayList<>();
        Object o;
        while ((o = pgpFact.nextObject()) != null) {

            // Please note the line:
            // pgpFact = new JcaPGPObjectFactory(obj.getDataStream());
            if (o instanceof PGPCompressedData) {
                // Has data stream
                PGPCompressedData obj = (PGPCompressedData)o;
                System.out.printf("%s", dumpPGPCompressedData(obj, "\t"));
                pgpFact = new JcaPGPObjectFactory(obj.getDataStream());
                continue; }

            if (o instanceof PGPSignature) {
                System.out.printf("%s", dumpPGPSignature((PGPSignature)o, "\t"));
                continue; }
            if (o instanceof PGPSignatureList) {
                System.out.printf("%s", dumpPGPSignatureList((PGPSignatureList)o, "\t"));
                continue; }
            if (o instanceof PGPSecretKeyRing) {
                System.out.printf("%s", dumpPGPSecretKeyRing((PGPSecretKeyRing)o, "\t"));
                continue; }
            if (o instanceof PGPPublicKeyRing) {
                System.out.printf("%s", dumpPGPPublicKeyRing((PGPPublicKeyRing)o, "\t"));
                continue; }
            if (o instanceof PGPLiteralData) {
                System.out.printf("%s", dumpPGPLiteralData((PGPLiteralData)o, "\t"));
                continue; }
            if (o instanceof PGPEncryptedDataList) {
                // Has stream
                System.out.printf("%s", dumpPGPEncryptedDataList((PGPEncryptedDataList)o, "\t"));
                continue; }
            if (o instanceof PGPOnePassSignature) {
                System.out.printf("%s", dumpPGPOnePassSignature((PGPOnePassSignature)o, "\t"));
                continue; }
            if (o instanceof PGPOnePassSignatureList) {
                System.out.printf("%s", dumpPGPOnePassSignatureList((PGPOnePassSignatureList)o, "\t"));
                continue; }
            if (o instanceof PGPMarker) {
                System.out.printf("%s", dumpPGPMarker((PGPMarker)o, "\t"));
                continue; }
            unexpected.add(o);
        }
        if (unexpected.size() > 0) {
            System.out.print("\tUnexpected:\n");
            for (Object e : unexpected.toArray()) {
                System.out.printf("\t\tClass: %s\n", e.getClass().getName());
            }
        }
    }



    static private void showBCPGOutputStream() throws IOException, PGPException {

        String outputFile;
        BCPGOutputStream basicOutputStream;
        ArmoredOutputStream armoredOutputStream;
        ByteArrayOutputStream buffer;


        UserIDPacket userIDPacket = new UserIDPacket("user@email.org");
        outputFile = "data/packet1.bgp";
        basicOutputStream = new BCPGOutputStream(getFileOutputStream(outputFile));
        userIDPacket.encode(basicOutputStream);
        basicOutputStream.close();
        System.out.printf("gpg --list-packet %s\n", outputFile);

        outputFile = "data/packet1.agp";
        buffer = new ByteArrayOutputStream();
        basicOutputStream = new BCPGOutputStream(buffer);
        userIDPacket.encode(basicOutputStream);
        armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(new File(outputFile)));
        armoredOutputStream.write(buffer.toByteArray());
        basicOutputStream.close();
        armoredOutputStream.close();
        System.out.printf("gpg --list-packet %s\n", outputFile);

        outputFile = "data/packet2.bgp";
        basicOutputStream = new BCPGOutputStream(getFileOutputStream(outputFile));
        UserIDPacket userIDPacket1 = new UserIDPacket("user1@email.org");
        UserIDPacket userIDPacket2 = new UserIDPacket("user2@email.org");
        userIDPacket1.encode(basicOutputStream);
        userIDPacket2.encode(basicOutputStream);
        basicOutputStream.close();
        System.out.printf("gpg --list-packet %s\n", outputFile);

        outputFile = "data/packet1.agp";
        buffer = new ByteArrayOutputStream();
        basicOutputStream = new BCPGOutputStream(buffer);
        userIDPacket1.encode(basicOutputStream);
        userIDPacket2.encode(basicOutputStream);
        armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(new File(outputFile)));
        armoredOutputStream.write(buffer.toByteArray());
        basicOutputStream.close();
        armoredOutputStream.close();
        System.out.printf("gpg --list-packet %s\n", outputFile);







        PGPKeyPair kp = createRsaKeyPair();
        PGPKeyPair[] keyPairs1 = {kp};
        PGPKeyRingGenerator keyRingGen = getKeyRingGenerator(keyPairs1,
                "user@email.org",
                "password");
        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();



//        outputFile = "data/packet3.bgp";
//        System.out.printf("Create 1 Public Key Ring and write it to \"%s\"\n", outputFile);
//        basicOutputStream = new BCPGOutputStream(getFileOutputStream(outputFile));
//        pubRing.encode(basicOutputStream);
//        basicOutputStream.close();
//        System.out.printf("gpg --list-packet %s\n", outputFile);
//
//        outputFile = "data/packet4.agp";
//        FileOutputStream fstream = getFileOutputStream(outputFile);
//        pubRing.encode(fstream);
//        basicOutputStream.close();
//        System.out.printf("gpg --list-packet %s\n", outputFile);





//        PublicKeyPacket publicKeyPacket = new PublicKeyPacket(pubKey.getAlgorithm(), pubKey.getCreationTime(), pubKey.);

//        basicOutputStream.writePacket();
//        basicOutputStream.writeObject();


    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            showByteArrayStreams();
            showCompression();

            System.out.println("====================================================");
            showArmoredStreams();
            System.out.println("====================================================");
            showBCPGInputStream("data/secret-keyring.pgp");
            System.out.println("====================================================");
            showBCPGInputStream("data/detached-signature.pgp");
            System.out.println("====================================================");
            showBCPGInputStream("data/document.txt.bpg");
            System.out.println("====================================================");

            showBCPGOutputStream();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
