package com.beurive;

import java.io.*;


public class Main {

    // InputStream (java.io)
    //    FileInputStream (java.io)
    //        PipeInputStream in Process (java.lang)
    //        SocketInputStream (java.net)
    //        WDropTargetContextPeerFileStream (sun.awt.windows)

    static private void showFileInputStream() throws FileNotFoundException, IOException {
        FileInputStream stream;
        String filePath = "./data/text-file.txt";

        byte[] buffer = new byte[10];
        stream = new FileInputStream(filePath);
        stream.read(buffer);
        stream.close();
    }

    public static void main(String[] args) {
    }
}
