package com.beurive;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.util.encoders.Hex;

public class Main {

    public static void main(String[] args) {
        SHA512Digest digester = new SHA512Digest();
        System.out.println("Name:        " + digester.getAlgorithmName());
        System.out.println("Digest size: " + digester.getDigestSize() + "\n");

        byte[] input = Hex.decode("012345678901234567890123456789");
        byte[] output = new byte[digester.getDigestSize()];
        digester.update(input, 0, input.length);
        digester.doFinal(output, 0);
        System.out.println("Input:       \"" + new String(Hex.encode(input)) + "\"");
        System.out.println("Digest:      " + new String(Hex.encode(output)) + "\n");

        input = Hex.decode("");
        digester.reset();
        digester.update(input, 0, input.length);
        digester.doFinal(output, 0);
        System.out.println("Input:       \"" + new String(Hex.encode(input)) + "\"");
        System.out.println("Digest:      " + new String(Hex.encode(output)));
    }
}
