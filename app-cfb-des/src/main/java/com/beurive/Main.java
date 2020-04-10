package com.beurive;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class Main {

    public static void main(String[] args) {
        // The "clear text" (its length must be a multiple of 1 byte).
        // Here, "clear text" is 6 bytes long.
        byte[] input = Hex.decode("4e6f77206973");
        // The encryption/decryption key (its length must be exactly 8 bytes).
        byte[] key = Hex.decode("0123456789abcdef");
        // The initialisation vector for the CFC mode (its length must be exactly 8 bytes).
        byte[] iv = Hex.decode("0123456789000000");

        // Create the cypher: using DES in Cipher feedback (CFB) mode.
        // The second parameter represents the length, in bits, of the blocks processed by the cipher.
        // It must be a multiple of 8 (bits).
        CFBBlockCipher engine = new CFBBlockCipher(new DESEngine(), 8); // each input block is 1 byte long.
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

        // Initialise the cypher. Required data are:
        //   * the key (for DES)
        //   * the initialization vector (for CFB)
        //   * the action: encrypt or decrypt
        ParametersWithIV param = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(true, param); // first parameter is "true" => encrypt

        // Encode
        byte[] encoded = new byte[input.length];
        int len = cipher.processBytes(input, 0, input.length, encoded, 0);
        try {
            cipher.doFinal(encoded, len);
        } catch (InvalidCipherTextException e) {
            System.out.println("ERROR: " + e.toString());
        }

        // Decode
        cipher.init(false, param); // first parameter is "false" => decrypt
        byte[] decoded = new byte[encoded.length];
        len = cipher.processBytes(encoded, 0, encoded.length, decoded, 0);
        try {
            cipher.doFinal(decoded, len);
        } catch (InvalidCipherTextException e) {
            System.out.println("ERROR: " + e.toString());
        }

        System.out.println("Key:        " + new String(Hex.encode(key)) + " (" + key.length + " bytes)");
        System.out.println("IV:         " + new String(Hex.encode(iv)) + " (" + iv.length + " bytes)");
        System.out.println("Clear text: " + new String(Hex.encode(input)) + " (" + input.length + " bytes)");
        System.out.println("Encoded:    " + new String(Hex.encode(encoded)));
        System.out.println("Decoded:    " + new String(Hex.encode(decoded)));
    }
}
