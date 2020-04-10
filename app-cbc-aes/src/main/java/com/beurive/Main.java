package com.beurive;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class Main {

    public static void main(String[] args) {
        // The "clear text" (its length must be a multiple of 16 bytes).
        byte[] input = Hex.decode("4e6f77206973207468652074696d65204e6f77206973207468652074696d6520");
        // The encryption/decryption key (its length must be exactly 128 bits, 192 bits or 256 bits).
        // * 128 bits: "0123456789abcdef0123456789abcdef");
        // * 192 bits: "0123456789abcdef0123456789abcdef0123456789abcdef");
        byte[] key = Hex.decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); // 256 bits
        // The initialisation vector for the CBC mode (its length must be exactly the same as the AES block size: 16 bytes).
        byte[] iv = Hex.decode("aabbccddaabbccddaabbccddaabbccdd");

        // Create the cypher: using AES in Cipher block chaining (CBC) mode.
        CBCBlockCipher engine = new CBCBlockCipher(new AESEngine());
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

        // Initialise the cypher. Required data are:
        //   * the key (for AES)
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
