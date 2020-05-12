package org.beurive.pgp;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import java.io.*;

public class Keyring {

    /**
     * Load a public keyring from a given input stream
     * @param inStream The input stream.
     * @return The method returns an instance of PGPPublicKeyRing.
     * @throws IOException
     * @throws UnexpectedDocumentException
     */

    static public PGPPublicKeyRing loadPublicKeyring(BufferedInputStream inStream) throws IOException, PGPException, UnexpectedDocumentException {
        PGPObjectFactory pgpObjectFactory = Document.getObjectFactory(inStream);
        Object o = pgpObjectFactory.nextObject();
        if (! (o instanceof PGPPublicKeyRing)) {
            throw new UnexpectedDocumentException(String.format("Unexpected packet type: %s (instead of %s).",
                    o.getClass().getName(),
                    PGPPublicKeyRing.class.getName()));
        }
        inStream.close();
        return (PGPPublicKeyRing)o;
    }

    /**
     * Lead a pblic keyring from a file.
     * @param inPath Path to the file.
     * @return The method returns an instance of PGPPublicKeyRing.
     * @throws IOException
     * @throws PGPException
     * @throws UnexpectedDocumentException
     */

    static public PGPPublicKeyRing loadPublicKeyring(String inPath) throws IOException, PGPException, UnexpectedDocumentException {
        return loadPublicKeyring(new BufferedInputStream(new FileInputStream(new File(inPath))));
    }

    /**
     * Load a secret keyring from a given input stream
     * @param inStream The input stream.
     * @return The method returns an instance of PGPSecretKeyRing.
     * @throws IOException
     * @throws UnexpectedDocumentException
     */

    static public PGPSecretKeyRing loadSecretKeyring(BufferedInputStream inStream) throws IOException, PGPException, UnexpectedDocumentException {
        PGPObjectFactory pgpObjectFactory = Document.getObjectFactory(inStream);
        Object o = pgpObjectFactory.nextObject();
        if (! (o instanceof PGPSecretKeyRing)) {
            throw new UnexpectedDocumentException(String.format("Unexpected packet type: %s (instead of %s).",
                    o.getClass().getName(),
                    PGPSecretKeyRing.class.getName()));
        }
        inStream.close();
        return (PGPSecretKeyRing)o;
    }

    /**
     * Load a secret keyring from a file.
     * @param inPath Path to the file.
     * @return The method returns an instance of PGPSecretKeyRing.
     * @throws IOException
     * @throws PGPException
     * @throws UnexpectedDocumentException
     */

    static public PGPSecretKeyRing loadSecretKeyring(String inPath) throws IOException, PGPException, UnexpectedDocumentException {
        return loadSecretKeyring(new BufferedInputStream(new FileInputStream(new File(inPath))));
    }

    /**
     * Return the private key associated to a secret keyring master key.
     * @param inKeyRing The secret keyring.
     * @param inPassPhrase The passphrase used to decrypt the private key.
     * @return The method returns an instance of PGPPrivateKey.
     */

    static public PGPPrivateKey getMasterPrivateKey(PGPSecretKeyRing inKeyRing, String inPassPhrase) throws PGPException {
        return inKeyRing.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(inPassPhrase.toCharArray()));
    }

    /**
     * Return he private key associated with a secret key identified by its ID.
     * @param inKeyRing The secret keyring.
     * @param inId The ID of the key.
     * @param inPassPhrase The passphrase used to decrypt the private key.
     * @return If the ID exists, then method returns an instance of PGPPrivateKey.
     * Otherwise, the methof returns the value null.
     * @throws PGPException
     */
    static public PGPPrivateKey getPrivateKeyById(PGPSecretKeyRing inKeyRing, long inId, String inPassPhrase) throws PGPException {
        PGPSecretKey key = inKeyRing.getSecretKey(inId);
        if (null == key) {
            return null;
        }
        return key.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(inPassPhrase.toCharArray()));
    }
}
