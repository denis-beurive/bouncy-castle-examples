package org.beurive.pgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import java.io.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

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

    /**
     * Extract the secret keys from a secret keyring.
     * @param inKeyRing The secret keyring that contains the keys to extract.
     * @param inUsedForSigning Flag that tells whether the method should return the only the subkeys suitable for
     * signing or not.
     * @return The method returns an array of secret keys.
     */

    static public PGPSecretKey[] getSecretKeys(PGPSecretKeyRing inKeyRing, boolean inUsedForSigning) {
        List<PGPSecretKey> keys = new ArrayList<PGPSecretKey>();
        Iterator<PGPSecretKey> it = inKeyRing.getSecretKeys();
        while(it.hasNext()) {
            PGPSecretKey secretKey = it.next();
            if (inUsedForSigning && (! secretKey.isSigningKey())) continue;
            keys.add(secretKey);
        }
        return keys.toArray(new PGPSecretKey[0]);
    }

    /**
     * Extract the public keys from a secret keyring.
     * @param inKeyRing The secret keyring that contains the keys to extract.
     * @return The method returns an array of public keys.
     */

    static public PGPPublicKey[] getPublicKeys(PGPSecretKeyRing inKeyRing) {
        List<PGPPublicKey> keys = new ArrayList<PGPPublicKey>();
        Iterator<PGPSecretKey> it = inKeyRing.getSecretKeys();
        while(it.hasNext()) {
            keys.add(it.next().getPublicKey());
        }
        return keys.toArray(new PGPPublicKey[0]);
    }

    /**
     * Extract the public keys from a public keyring.
     * @param inKeyRing The public keyring that contains the keys to extract.
     * @return The method returns an array of public keys.
     */

    static public PGPPublicKey[] getPublicKeys(PGPPublicKeyRing inKeyRing) {
        List<PGPPublicKey> keys = new ArrayList<PGPPublicKey>();
        Iterator<PGPPublicKey> it = inKeyRing.getPublicKeys();
        while(it.hasNext()) {
            keys.add(it.next());
        }
        return keys.toArray(new PGPPublicKey[0]);
    }

    /**
     * Create a textual representation of a given public keyring.
     * @param inKeyRing The public keyring to dump.
     * @param inIndent Indent prepended to each line.
     * @return The method returns a textual representation of the given public keyring.
     */

    static public StringBuilder dumpPublic(PGPPublicKeyRing inKeyRing, String inIndent) {
        StringBuilder text = new StringBuilder();
        PGPPublicKey[] keys = getPublicKeys(inKeyRing);
        for (PGPPublicKey k: keys) {
            text.append(String.format("%sID: %16X (master:%s)\n",
                    inIndent,
                    k.getKeyID(),
                    k.isMasterKey() ? "yes" : "no"));
            if (k.isMasterKey()) {
                text.append(String.format("%s    users:%s\n",
                        inIndent,
                        getUsers(k).stream().map(Object::toString).collect(Collectors.joining(", "))));
            }
        }
        return text;
    }

    /**
     * Create a textual representation of a given public keyring.
     * @param inKeyRing The public keyring to dump.
     * @return The method returns a textual representation of the given public keyring.
     */

    static public StringBuilder dumpPublic(PGPPublicKeyRing inKeyRing) {
        return dumpPublic(inKeyRing, "");
    }

    /**
     * Dump a given public keyring into a file identified by its path.
     * @param inKeyRing The keyring to dump.
     * @param inPath The path to the file.
     * @throws IOException
     */

    static public void dumpPublicToPath(PGPPublicKeyRing inKeyRing, String inPath) throws
            IOException {
        ArmoredOutputStream out = new ArmoredOutputStream(new FileOutputStream(new File(inPath)));
        inKeyRing.encode(out);
        out.close();
    }

    /**
     * Create a textual representation of a given secret key users.
     * @param inKey The secret key.
     * @return The method returns a textual representation of the given secret key users.
     */

    static public ArrayList<String> getUsers(PGPSecretKey inKey) {
        ArrayList<String> users = new ArrayList<>();
        Iterator<String> it = inKey.getUserIDs();
        while (it.hasNext()) {
            users.add(it.next());
        }
        return users;
    }

    /**
     * Create a textual representation of a given public key users.
     * @param inKey The secret key.
     * @return The method returns a textual representation of the given public key users.
     */

    static public ArrayList<String> getUsers(PGPPublicKey inKey) {
        ArrayList<String> users = new ArrayList<>();
        Iterator<String> it = inKey.getUserIDs();
        while (it.hasNext()) {
            users.add(it.next());
        }
        return users;
    }

    /**
     * Create a textual representation of a given secret keyring.
     * @param inKeyRing The secret keyring to dump.
     * @param inIndent Indent prepended to each line.
     * @return The method returns a textual representation of the given secret keyring.
     */

    static public StringBuilder dumpSecret(PGPSecretKeyRing inKeyRing, String inIndent) {
        StringBuilder text = new StringBuilder();
        PGPSecretKey[] keys = getSecretKeys(inKeyRing, false);
        for (PGPSecretKey k: keys) {
            text.append(String.format("%sID: %16X (master:%s, signing: %s)\n",
                    inIndent,
                    k.getKeyID(),
                    k.isMasterKey() ? "yes" : "no",
                    k.isSigningKey() ? "yes" : "no"));
            if (k.isMasterKey()) {
                text.append(String.format("%s    users:%s\n",
                        inIndent,
                        getUsers(k).stream().map(Object::toString).collect(Collectors.joining(", "))));
            }
        }
        return text;
    }

    /**
     * Create a textual representation of a given secret keyring.
     * @param inKeyRing The secret keyring to dump.
     * @return The method returns a textual representation of the given secret keyring.
     */

    static public StringBuilder dumpSecret(PGPSecretKeyRing inKeyRing) {
        return dumpSecret(inKeyRing, "");
    }

    /**
     * Dump a given secret keyring into a file identified by its path.
     * @param inKeyRing The keyring to dump.
     * @param inPath The path to the file.
     * @throws IOException
     */

    static public void dumpSecretToPath(PGPSecretKeyRing inKeyRing, String inPath) throws
            IOException {
        ArmoredOutputStream out = new ArmoredOutputStream(new FileOutputStream(new File(inPath)));
        inKeyRing.encode(out);
        out.close();
    }
}
