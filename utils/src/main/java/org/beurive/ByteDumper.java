package org.beurive;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;

enum Format {
    hex,
    bin
}

public class ByteDumper {

    private int __inBytesPerLine = 16;
    private Format __format = Format.hex;
    private String __indent = "";

    public ByteDumper() { }

    public ByteDumper(int inBytesPerLine) {
        this.__inBytesPerLine = inBytesPerLine;
    }

    public void setIndent(String inIndent) {
        this.__indent = inIndent;
    }

    public void setHex() { this.__format = Format.hex; }

    public void setBin() { this.__format = Format.bin; }

    private String __bytesToStringDump(byte[] inBytes) {
        StringBuilder result = new StringBuilder();
        for(byte b: inBytes) {
            switch (this.__format) {
                case hex -> {
                    result.append(String.format("%02X ", Byte.toUnsignedInt(b)));
                }
                case bin -> {
                    String bin = String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
                    result.append(String.format("%8s ", bin));
                }
            }
        }
        return result.toString();
    }

    public String dump(String inPath) throws FileNotFoundException, IOException {
        FileInputStream input = new FileInputStream(inPath);
        byte[] data = input.readAllBytes();
        input.close();
        return this.dump(data);
    }

    public String dump(byte[] data) {

        final int byte_per_line = 16;
        int length = data.length;
        int line_count = (int)Math.floor(length / this.__inBytesPerLine);
        int reminder = length % byte_per_line;

        StringBuilder result = new StringBuilder();

        // Entire lines
        for (int line_index=0; line_index<line_count; line_index++) {
            int from = line_index * byte_per_line;
            int to = from + byte_per_line;
            byte[] line = Arrays.copyOfRange(data, from, to);
            String printable = (new String(line)).replaceAll("\\P{Print}", ".");
            result.append(String.format("%s%s | %s\n",
                    this.__indent,
                    __bytesToStringDump(line),
                    printable));
        }

        // Reminder
        int from = line_count * byte_per_line;
        int to = from + reminder;
        byte[] line = Arrays.copyOfRange(data, from, to);
        String printable = (new String(line)).replaceAll("\\P{Print}", ".");

        int delta = 0;
        switch (this.__format) {
            case hex -> {
                delta = 3;
            }
            case bin -> {
                delta = 9;
            }
        }
        result.append(String.format("%s%s%s | %s\n",
                this.__indent,
                __bytesToStringDump(line),
                " ".repeat(delta * (byte_per_line - reminder)),
                printable));
        return result.toString();
    }
}
