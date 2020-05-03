package com.beurive;

import java.io.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.attr.ImageAttribute;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.util.Arrays;

public class Main {

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

    static private String dumpPGPSignature(PGPSignature o, String inIndent) {
        StringBuilder res = new StringBuilder(String.format("%sPGPSignature:\n", inIndent));
        res.append(String.format("%s\tVersion: %d\n", inIndent, o.getVersion()));
        res.append(String.format("%s\tCreation time: %s\n", inIndent, o.getCreationTime().toString()));
        res.append(String.format("%s\tHash Algorithm: %d\n", inIndent, o.getHashAlgorithm()));
        res.append(String.format("%s\tKey Algorithm: %d\n", inIndent, o.getKeyAlgorithm()));
        res.append(String.format("%s\tKey ID: %X\n", inIndent, o.getKeyID()));
        res.append(String.format("%s\tType: %d\n", inIndent, o.getSignatureType()));
        res.append(String.format("%s\tCertification ? %s\n", inIndent, o.isCertification() ? "yes" : "no"));
        res.append(String.format("%s\tHas sub packets ? %s\n", inIndent, o.hasSubpackets() ? "yes" : "no"));

        if (o.hasSubpackets()) {
            res.append(String.format("%s\tHas hashed sub-packet count: %d\n", inIndent, o.getHashedSubPackets().size()));
            res.append(dumpSignatureSubPackets(o.getHashedSubPackets().toArray(), String.format("%s\t\t", inIndent)));
            res.append(String.format("%s\tHas un-hashed sub-packet count: %d\n", inIndent, o.getUnhashedSubPackets().size()));
            res.append(dumpSignatureSubPackets(o.getUnhashedSubPackets().toArray(), String.format("%s\t\t", inIndent)));
        }
        return res.toString();
    }

    static private String dumpPGPSignatureList(PGPSignatureList o, String inIndent) {
        StringBuilder res = new StringBuilder(String.format("%sPGPSignatureList:\n", inIndent));
        res.append(String.format("%s\tNumber of signatures: %d\n", inIndent, o.size()));
        res.append(String.format("%s\tSignatures:\n", inIndent));
        for(PGPSignature s: o) {
            res.append(dumpPGPSignature(s, String.format("%s\t", inIndent)));
        }
        return res.toString();
    }

    static private String dumpImageAttribute(ImageAttribute o, String inIndent) {
        StringBuilder res = new StringBuilder(String.format("%sImageAttribute:\n", inIndent));
        res.append(String.format("%s\tEncoding: %d\n", inIndent, o.getEncoding()));
        res.append(String.format("%s\tImage data length: %d\n", inIndent, o.getImageData().length));
        return res.toString();
    }

    static private String dumpPGPSecretKey(PGPSecretKey o, String inIndent) {
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
        StringBuilder res = new StringBuilder(String.format("%sPGPSecretKeyRing:\n", inIndent));
        res.append(String.format("%s", res.toString()));
        for(PGPSecretKey s: o) {
            res.append(dumpPGPSecretKey(s, String.format("%s\t", inIndent)));
        }
        return res.toString();
    }

    static private String dumpPGPPublicKey(PGPPublicKey o, String inIndent) {
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

    static private String dumpPGPPublicKeyRing(PGPPublicKeyRing o, String inIndent) {
        StringBuilder res = new StringBuilder(String.format("%sPGPPublicKeyRing:\n", inIndent));
        res.append(String.format("%s\tPublic keys:\n", inIndent));
        res.append(String.format("%s", res.toString()));
        Iterator<PGPPublicKey> keys = o.getPublicKeys();
        while(keys.hasNext()) {
            res.append(dumpPGPPublicKey(keys.next(), String.format("%s\t", inIndent)));
        }
        return res.toString();
    }

    static private String dumpPGPCompressedData(PGPCompressedData o, String inIndent) throws PGPException, IOException {
        StringBuilder res = new StringBuilder(String.format("%sPGPCompressedData:\n", inIndent));
        res.append(String.format("%s\tAlgorithm: %d\n", inIndent, o.getAlgorithm()));
        return res.toString();
    }

    static private String dumpPGPLiteralData(PGPLiteralData o, String inIndent) throws IOException {
        StringBuilder res = new StringBuilder(String.format("%sPGPLiteralData:\n", inIndent));
        res.append(String.format("%s\tFormat: %d\n", inIndent, o.getFormat()));
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
        StringBuilder res = new StringBuilder(String.format("%sPGPOnePassSignature:\n", inIndent));
        res.append(String.format("%s\tID: %X:\n", inIndent, o.getKeyID()));
        res.append(String.format("%s\tType: %d:\n", inIndent, o.getSignatureType()));
        res.append(String.format("%s\tHash algorithm: %d:\n", inIndent, o.getHashAlgorithm()));
        res.append(String.format("%s\tKey algorithm: %d:\n", inIndent, o.getKeyAlgorithm()));
        res.append(String.format("%s\tData length: %d:\n", inIndent, o.getEncoded().length));
        return res.toString();
    }

    static private String dumpPGPOnePassSignatureList(PGPOnePassSignatureList o, String inIndent) throws IOException {
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

    public static void main(String[] args) {
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
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
