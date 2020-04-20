package com.beurive;

import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.ArmoredInputStream;

public class Main {

    /**
     * Illustrates the use of armored streams.
     *
     * InputStream (java.io)
     *     ArmoredInputStream (org.bouncycastle.bcpg)
     *
     * OutputStream (java.io)
     *     ArmoredOutputStream (org.bouncycastle.bcpg)
     *
     * @throws IOException
     */

    static private void showArmoredInputOutputStream() throws IOException {
        String armoredFile = "./data/armored-output.txt";
        String message = "This is a text";

        ArmoredOutputStream out_stream = new ArmoredOutputStream(new FileOutputStream(armoredFile));
        out_stream.write(message.getBytes());
        out_stream.close();

        ArmoredInputStream in_stream = new ArmoredInputStream(new FileInputStream(armoredFile));
        byte[] content = in_stream.readAllBytes();
        assert(0 == message.compareTo(new String(content, Charset.forName("ASCII"))));
    }

    public static void main(String[] args) {
        try {
            showArmoredInputOutputStream();
        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
        }
    }
}
