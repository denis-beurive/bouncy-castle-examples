package com.beurive;

import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class Main {

    public static void main(String[] args) {
        // The "clear text" (its length must be a multiple of 8 bytes).
        byte[] input = Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20");
        // The encryption/decryption key (its length must be exactly 8 bytes).
        byte[] key = Hex.decode("0123456789abcdef");
        // The initialisation vector for the CBC mode (its length must be exactly the same as the DES block size: 8 bytes).
        byte[] iv = Hex.decode("0123456789000000");

        // Create the cypher: using 3DES in Cipher block chaining (CBC) mode.
        CBCBlockCipher engine = new CBCBlockCipher(new DESedeEngine());
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

        // Initialise the cypher. Required data are:
        //   * the key (for DES)
        //   * the initialization vector (for CBC)
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
