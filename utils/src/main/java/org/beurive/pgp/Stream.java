package org.beurive.pgp;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;

import java.io.*;

public class Stream {

    /**
     * Get a buffered ArmoredInputStream from a file identified by its given path.
     * @param in_path Path to the input file.
     * @return An ArmoredInputStream from the file which path was given.
     * @throws IOException
     */

    static public ArmoredInputStream getBufferedArmoredInputStreamFromFile(String in_path) throws IOException {
        return new ArmoredInputStream(new BufferedInputStream(new FileInputStream(new File(in_path))));
    }

    /**
     * Create a buffered ArmoredOutputStream to a file.
     * @param inPath Path to the output file.
     * @return a new ArmoredOutputStream.
     * @throws IOException
     */

    static public ArmoredOutputStream getBufferedArmoredOutputStreamToFile(String inPath) throws IOException {
        return new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(new File(inPath))));
    }
}
