package com.beurive;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;

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

        List<PGPSignature> pgpSignatureList = new ArrayList<>();
        List<PGPSignatureList> pgpSignatureListList = new ArrayList<>();
        List<PGPSecretKeyRing> pgpSecretKeyRingList = new ArrayList<>();
        List<PGPPublicKeyRing> publicKeyRingList = new ArrayList<>();
        List<PGPCompressedData> pgpCompressedDataList = new ArrayList<>();
        List<PGPLiteralData> pgpLiteralDataList = new ArrayList<>();
        List<PGPEncryptedData> pgpEncryptedDataList = new ArrayList<>();
        List<PGPEncryptedDataList> pgpEncryptedDataListList = new ArrayList<>();
        List<PGPOnePassSignature> pgpOnePassSignatureList = new ArrayList<>();
        List<PGPOnePassSignatureList> pgpOnePassSignatureListList = new ArrayList<>();
        List<PGPMarker> pgpMarkerList = new ArrayList<>();
        List<Object> unexpected = new ArrayList<>();

        Object o;
        while ((o = pgpFact.nextObject()) != null) {
            System.out.printf("- %s\n", o.getClass().getName());
            if (o instanceof PGPSignature) {
                // No stream
                pgpSignatureList.add((PGPSignature)o);
                continue; }
            if (o instanceof PGPSignatureList) {
                // No stream
                PGPSignatureList obj = (PGPSignatureList)o;
                pgpSignatureListList.add(obj);
                for (PGPSignature signature: obj) {
                    // ...
                }
                continue; }
            if (o instanceof PGPSecretKeyRing) {
                // No stream
                PGPSecretKeyRing obj = (PGPSecretKeyRing)o;
                pgpSecretKeyRingList.add(obj);
                for (PGPSecretKey secretKey: obj) {
                    // ...
                }
                continue; }
            if (o instanceof PGPPublicKeyRing) {
                // No stream
                PGPPublicKeyRing obj = (PGPPublicKeyRing)o;
                publicKeyRingList.add(obj);
                for (PGPPublicKey publicKey: obj) {
                    // ...
                }
                continue; }
            if (o instanceof PGPCompressedData) {
                // Has stream
                PGPCompressedData obj = (PGPCompressedData)o;
                pgpCompressedDataList.add(obj);
                // Reassign the input stream of the PGP Object Factory.
                pgpFact = new JcaPGPObjectFactory(obj.getDataStream());
                continue; }
            if (o instanceof PGPLiteralData) {
                // Has stream
                PGPLiteralData obj = (PGPLiteralData)o;
                pgpLiteralDataList.add(obj);
                InputStream dataIn = obj.getInputStream();
                // Consume the data bytes from the object.
                dataIn.readAllBytes();
                continue; }
            if (o instanceof PGPEncryptedDataList) {
                // Has stream
                PGPEncryptedDataList obj = (PGPEncryptedDataList)o;
                pgpEncryptedDataListList.add(obj);
                for (PGPEncryptedData encryptedData : obj) {
                    pgpEncryptedDataList.add(encryptedData);
                    InputStream encryptedDataStream = encryptedData.getInputStream();
                    // Consume the data bytes from the object.
                    encryptedDataStream.readAllBytes(); // consume bytes.
                }
                continue; }
            if (o instanceof PGPOnePassSignature) {
                // No stream
                pgpOnePassSignatureList.add((PGPOnePassSignature)o);
                continue; }
            if (o instanceof PGPOnePassSignatureList) {
                // No stream
                PGPOnePassSignatureList obj = (PGPOnePassSignatureList)o;
                pgpOnePassSignatureListList.add(obj);
                for (PGPOnePassSignature onePassSignature: obj) {
                    // ...
                }
                continue; }
            if (o instanceof PGPMarker) {
                // No stream
                pgpMarkerList.add((PGPMarker)o);
                continue; }
            unexpected.add(o);
        }

        System.out.printf("%s:\n", InPgpDocument);

        if (pgpSignatureList.size() > 0) {
            System.out.print("\tPGPSignature:\n");
            for (Object e : pgpSignatureList.toArray()) {
                PGPSignature obj = (PGPSignature)e;
                System.out.printf("\t\tKey: %X\n", obj.getKeyID());
                System.out.printf("\t\tVersion: %d\n", obj.getVersion());
            }
        }

        if (pgpCompressedDataList.size() > 0) {
            System.out.print("\tPgpCompressedDataList:\n");
            for (Object e : pgpCompressedDataList.toArray()) {
                PGPCompressedData obj = (PGPCompressedData)e;
                System.out.printf("\t\tAlgorithm %d:\n", obj.getAlgorithm());
            }
        }

        if (pgpSignatureListList.size() > 0) {
            System.out.print("\tPGPSignatureList:\n");
            for (Object e : pgpSignatureListList.toArray()) {
                PGPSignatureList obj = (PGPSignatureList)e;
                System.out.printf("\t\tSize: %d\n", obj.size());
            }
        }

        if (pgpSecretKeyRingList.size() > 0) {
            System.out.print("\tPGPSecretKeyRing:\n");
            for (Object e : pgpSecretKeyRingList.toArray()) {
                PGPSecretKeyRing obj = (PGPSecretKeyRing)e;
                System.out.printf("\t\tPublic key ID: %X\n", obj.getPublicKey().getKeyID());
                System.out.printf("\t\tSecret key ID: %X\n", obj.getSecretKey().getKeyID());
            }
        }

        if (publicKeyRingList.size() > 0) {
            System.out.print("\tPGPPublicKeyRing:\n");
            for (Object e : publicKeyRingList.toArray()) {
                PGPPublicKeyRing obj = (PGPPublicKeyRing)e;
                System.out.printf("\t\tPublic key ID: %X\n", obj.getPublicKey().getKeyID());
            }
        }

        if (pgpLiteralDataList.size() > 0) {
            System.out.print("\tPGPLiteralData:\n");
            for (Object e : pgpLiteralDataList.toArray()) {
                PGPLiteralData obj = (PGPLiteralData)e;
                System.out.printf("\t\tFile name: %s\n", obj.getFileName());
            }
        }

        if (pgpLiteralDataList.size() > 0) {
            System.out.print("\tPGPCompressedData:\n");
            for (Object e : pgpLiteralDataList.toArray()) {
                PGPLiteralData obj = (PGPLiteralData)e;
                System.out.printf("\t\tFile name: %s\n", obj.getFileName());
                System.out.printf("\t\tFormat: %d\n", obj.getFormat());
                System.out.printf("\t\tModification time: %s\n", obj.getModificationTime().toString());
            }
        }

        if (pgpEncryptedDataListList.size() > 0) {
            System.out.print("\tPGPEncryptedDataList:\n");
            for (Object e : pgpEncryptedDataListList.toArray()) {
                PGPEncryptedDataList obj = (PGPEncryptedDataList)e;
                System.out.printf("\t\tSize: %d\n", obj.size());
            }
        }

        if (pgpOnePassSignatureList.size() > 0) {
            System.out.print("\tPGPOnePassSignature:\n");
            for (Object e : pgpOnePassSignatureList.toArray()) {
                PGPOnePassSignature obj = (PGPOnePassSignature)e;
                System.out.printf("\t\tType: %d\n", obj.getSignatureType());
                System.out.printf("\t\tHash algorithm: %d\n", obj.getHashAlgorithm());
                System.out.printf("\t\tKey ID: %X\n", obj.getKeyID());
            }
        }

        if (pgpOnePassSignatureListList.size() > 0) {
            System.out.print("\tPGPOnePassSignatureList:\n");
            for (Object e : pgpOnePassSignatureListList.toArray()) {
                PGPOnePassSignatureList obj = (PGPOnePassSignatureList)e;
                System.out.printf("\t\tSize: %d\n", obj.size());
            }
        }

        if (pgpMarkerList.size() > 0) {
            System.out.print("\tPGPMarker:\n");
            for (Object e : pgpMarkerList.toArray()) {
                PGPMarker obj = (PGPMarker)e;
                System.out.printf("\t\tHash Code: %d\n", obj.hashCode());
            }
        }

        if (pgpEncryptedDataList.size() > 0) {
            System.out.print("\tPGPEncryptedData:\n");
            for (Object e : pgpEncryptedDataList.toArray()) {
                PGPEncryptedData obj = (PGPEncryptedData)e;
                System.out.printf("\t\tHash Code: %d\n", obj.hashCode());
            }
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
            showArmoredStreams();
            showByteArrayStreams();
            showCompression();
            showBCPGInputStream("data/secret-keyring.pgp");
            showBCPGInputStream("data/detached-signature.pgp");
            showBCPGInputStream("data/document.txt.bpg");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
