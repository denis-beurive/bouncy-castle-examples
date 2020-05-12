package org.beurive.pgp;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;

/**
 * This class contains utilities for PGP documents.
 */

public class Document {

    /**
     * Test whether a document is "armored" or not.
     *
     * See https://tools.ietf.org/html/rfc4880#section-6.2
     *
     * @param inStream Stream that contains the document to test.
     * @return If the document is "armored", then the method returns the value true.
     * Otherwise, it returns the value false.
     */

    static public boolean isArmored(BufferedInputStream inStream) throws IOException {

        // An armored document begins with the following string of characters:
        // "-----BEGIN PGP"
        // Hex: 2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 47 50

        final int header_length = 14;

        if (inStream.available() < header_length) {
            return false;
        }
        byte[] expected = {0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20, 0x50, 0x47, 0x50};
        inStream.mark(0);
        for (int i=0; i<header_length; i++) {
            if (inStream.read() != expected[i]) {
                inStream.reset();
                return false;
            }
        }
        inStream.reset();
        return true;
    }

    /**
     * Return an input stream suitable for loading a given PGP document.
     * @param inStream Stream that contains the document to load.
     * @return The method returns an input stream suitable for loading the given PGP document.
     * @throws IOException
     */

    static public InputStream getStream(BufferedInputStream inStream) throws IOException {
        if (isArmored(inStream)) {
            return new ArmoredInputStream(inStream);
        }
        return inStream;
    }

    /**
     * Get an object factory for a given PGP document.
     * @param inStream Stream that contains the document.
     * @return The method returns an instance of JcaPGPObjectFactory.
     * @throws IOException
     * @throws PGPException
     */

    static public JcaPGPObjectFactory getObjectFactory(BufferedInputStream inStream) throws IOException, PGPException {
        inStream.mark(0);
        BCPGInputStream pgpObjectsReader = new BCPGInputStream(getStream(inStream));
        JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(pgpObjectsReader);
        Object o = objectFactory.nextObject();
        if (null == o) throw new PGPException("Invalid PGP document. This document does not contain any PHP packet.");
        if (o instanceof PGPCompressedData) {
            PGPCompressedData compressedData = (PGPCompressedData)o;
            return new JcaPGPObjectFactory(compressedData.getDataStream());
        }
        inStream.reset();
        return new JcaPGPObjectFactory(new BCPGInputStream(getStream(inStream)));
    }
}
