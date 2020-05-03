package com.beurive;

import java.io.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
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

    static private void dumpPGPSignature(PGPSignature o, String inIndent) {
        StringBuilder res = new StringBuilder(String.format("%sPGPSignature:\n", inIndent));
        res.append(String.format("%s\tVersion: %d\n", inIndent, o.getVersion()));
        res.append(String.format("%s\tCreation time: %s\n", inIndent, o.getCreationTime().toString()));
        res.append(String.format("%s\tHash Algorithm: %d\n", inIndent, o.getHashAlgorithm()));
        res.append(String.format("%s\tKey Algorithm: %d\n", inIndent, o.getKeyAlgorithm()));
        res.append(String.format("%s\tKey ID: %X\n", inIndent, o.getKeyID()));
        res.append(String.format("%s\tType: %d\n", inIndent, o.getSignatureType()));
        res.append(String.format("%s\tCertification ? %s\n", inIndent, o.isCertification() ? "yes" : "no"));
        res.append(String.format("%s\tHas sub packets ? %s\n", inIndent, o.hasSubpackets() ? "yes" : "no"));
        System.out.printf("%s", res.toString());
    }

    static private void dumpPGPSignatureList(PGPSignatureList o, String inIndent) {
        StringBuilder res = new StringBuilder(String.format("%sPGPSignatureList:\n", inIndent));
        res.append(String.format("%s\tNumber of signatures: %d\n", inIndent, o.size()));
        res.append(String.format("%s\tSignatures:\n", inIndent));
        System.out.printf("%s", res.toString());
        for(PGPSignature s: o) {
            dumpPGPSignature(s, String.format("%s\t", inIndent));
        }
    }

    static private void dumpPGPSecretKey(PGPSecretKey o, String inIndent) {
        StringBuilder res = new StringBuilder(String.format("%sPGPSecretKey:\n", inIndent));
        res.append(String.format("%s\tID: %X\n", inIndent, o.getKeyID()));
        res.append(String.format("%s\tIs master ley ? %s\n", inIndent, o.isMasterKey() ? "yes" : "no"));
        res.append(String.format("%s\tIs signing ley ? %s\n", inIndent, o.isSigningKey() ? "yes" : "no"));
        res.append(String.format("%s\tIs empty ? %s\n", inIndent, o.isPrivateKeyEmpty() ? "yes" : "no"));
        res.append(String.format("%s\tEncryption algorithm: %d\n", inIndent, o.getKeyEncryptionAlgorithm()));
        res.append(String.format("%s\tUser IDs:\n", inIndent));
        Iterator<String> id = o.getUserIDs();
        while (id.hasNext()) {
            res.append(String.format("%s\t\tUser: %s\n", inIndent, id.next()));
        }
        System.out.printf("%s", res.toString());
    }

    static private void dumpPGPSecretKeyRing(PGPSecretKeyRing o, String inIndent) {
        StringBuilder res = new StringBuilder(String.format("%sPGPSecretKeyRing:\n", inIndent));
        System.out.printf("%s", res.toString());
        for(PGPSecretKey s: o) {
            dumpPGPSecretKey(s, String.format("%s\t", inIndent));
        }
    }

    static private void dumpPGPPublicKey(PGPPublicKey o, String inIndent) {
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
        System.out.printf("%s", res.toString());
        Iterator<PGPSignature> sigs = o.getSignatures();
        while (sigs.hasNext()) {
            dumpPGPSignature(sigs.next(), String.format("%s\t", inIndent));
        }
    }

    static private void dumpPGPPublicKeyRing(PGPPublicKeyRing o, String inIndent) {
        StringBuilder res = new StringBuilder(String.format("%sPGPPublicKeyRing:\n", inIndent));
        res.append(String.format("%s\tPublic keys:\n", inIndent));
        System.out.printf("%s", res.toString());
        Iterator<PGPPublicKey> keys = o.getPublicKeys();
        while(keys.hasNext()) {
            dumpPGPPublicKey(keys.next(), String.format("%s\t", inIndent));
        }
    }

    static private void dumpPGPCompressedData(PGPCompressedData o, String inIndent) throws PGPException, IOException {
        StringBuilder res = new StringBuilder(String.format("%sPGPCompressedData:\n", inIndent));
        res.append(String.format("%s\tAlgorithm: %d\n", inIndent, o.getAlgorithm()));
        res.append(String.format("%s\tData length: %d\n", inIndent, o.getDataStream().readAllBytes().length));
        System.out.printf("%s", res.toString());
    }

    static private void dumpPGPLiteralData(PGPLiteralData o, String inIndent) throws IOException {
        StringBuilder res = new StringBuilder(String.format("%sPGPLiteralData:\n", inIndent));
        res.append(String.format("%s\tFormat: %d\n", inIndent, o.getFormat()));
        res.append(String.format("%s\tFile name: %s\n", inIndent, o.getFileName()));
        res.append(String.format("%s\tModification time: %s\n", inIndent, o.getModificationTime().toString()));
        res.append(String.format("%s\tData length: %d\n", inIndent, o.getInputStream().readAllBytes().length));
        System.out.printf("%s", res.toString());
    }

    static private void dumpPGPEncryptedData(PGPEncryptedData o, String inIndent) throws IOException {
        StringBuilder res = new StringBuilder(String.format("%sPGPEncryptedData:\n", inIndent));
        res.append(String.format("%s\tIntegrity protected ? %s\n", inIndent, o.isIntegrityProtected() ? "yes" : "no"));
        res.append(String.format("%s\tData length: %d\n", inIndent, o.getInputStream().readAllBytes().length));
        System.out.printf("%s", res.toString());
    }

    static private void dumpPGPEncryptedDataList(PGPEncryptedDataList o, String inIndent) throws IOException {
        StringBuilder res = new StringBuilder(String.format("%sPGPEncryptedDataList:\n", inIndent));
        Iterator<PGPEncryptedData> data = o.getEncryptedDataObjects();
        res.append(String.format("%s\tEncrypted data list:\n", inIndent));
        System.out.printf("%s", res.toString());
        while (data.hasNext()) {
            dumpPGPEncryptedData(data.next(), String.format("%s\t", inIndent));
        }
    }

    static private void dumpPGPOnePassSignature(PGPOnePassSignature o, String inIndent) throws IOException {
        StringBuilder res = new StringBuilder(String.format("%sPGPOnePassSignature:\n", inIndent));
        res.append(String.format("%s\tID: %X:\n", inIndent, o.getKeyID()));
        res.append(String.format("%s\tType: %d:\n", inIndent, o.getSignatureType()));
        res.append(String.format("%s\tHash algorithm: %d:\n", inIndent, o.getHashAlgorithm()));
        res.append(String.format("%s\tKey algorithm: %d:\n", inIndent, o.getKeyAlgorithm()));
        res.append(String.format("%s\tData length: %d:\n", inIndent, o.getEncoded().length));
        System.out.printf("%s", res.toString());
    }

    static private void dumpPGPOnePassSignatureList(PGPOnePassSignatureList o, String inIndent) throws IOException {
        StringBuilder res = new StringBuilder(String.format("%sPGPOnePassSignatureList:\n", inIndent));
        res.append(String.format("%s\tIs empty: %s\n", inIndent, o.isEmpty() ? "yes" : "no"));
        res.append(String.format("%s\tPGPOnePassSignature list:\n", inIndent));
        System.out.printf("%s", res.toString());
        Iterator<PGPOnePassSignature> sigs = o.iterator();
        while (sigs.hasNext()) {
            dumpPGPOnePassSignature(sigs.next(), String.format("%s\t", inIndent));
        }
    }

    static private void dumpPGPMarker(PGPMarker o, String inIndent) {
        System.out.printf("%sPGPMarker: %s\n", inIndent, o.getClass().getName());
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
            System.out.printf("- %s\n", o.getClass().getName());

            // Please note the line:
            // pgpFact = new JcaPGPObjectFactory(obj.getDataStream());
            if (o instanceof PGPCompressedData) {
                // Has data stream
                PGPCompressedData obj = (PGPCompressedData)o;
                dumpPGPCompressedData(obj, "\t");
                pgpFact = new JcaPGPObjectFactory(obj.getDataStream());
                continue; }

            if (o instanceof PGPSignature) {
                dumpPGPSignature((PGPSignature)o, "\t");
                continue; }
            if (o instanceof PGPSignatureList) {
                dumpPGPSignatureList((PGPSignatureList)o, "\t");
                continue; }
            if (o instanceof PGPSecretKeyRing) {
                dumpPGPSecretKeyRing((PGPSecretKeyRing)o, "\t");
                continue; }
            if (o instanceof PGPPublicKeyRing) {
                dumpPGPPublicKeyRing((PGPPublicKeyRing)o, "\t");
                continue; }
            if (o instanceof PGPLiteralData) {
                dumpPGPLiteralData((PGPLiteralData)o, "\t");
                continue; }
            if (o instanceof PGPEncryptedDataList) {
                // Has stream
                dumpPGPEncryptedDataList((PGPEncryptedDataList)o, "\t");
                continue; }
            if (o instanceof PGPOnePassSignature) {
                dumpPGPOnePassSignature((PGPOnePassSignature)o, "\t");
                continue; }
            if (o instanceof PGPOnePassSignatureList) {
                dumpPGPOnePassSignatureList((PGPOnePassSignatureList)o, "\t");
                continue; }
            if (o instanceof PGPMarker) {
                dumpPGPMarker((PGPMarker)o, "\t");
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
