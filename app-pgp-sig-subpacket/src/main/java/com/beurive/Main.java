/**
 * This file implements the following functionalities:
 * * generation of a single One Pass Signature (tag=4).
 * * generation of a "double* One Pass Signature (tag=4).
 * * generation of a Detached Signature (tag=2).
 * * verification of a single One Pass Signature (tag=4).
 * * verification of a Detached Signature (tag=2).
 */

package com.beurive;

import java.io.*;
import java.security.Security;

import java.util.Date;
import java.util.Iterator;

import org.beurive.pgp.Document;
import org.beurive.pgp.UnexpectedDocumentException;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.beurive.pgp.Keyring;
import org.beurive.pgp.Stream;


public class Main {

    static Date now = new Date();





    public static void main(String[] args) {
        // Declare the provider "BC" (for Bouncy Castle).
        Security.addProvider(new BouncyCastleProvider());

        try {

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
