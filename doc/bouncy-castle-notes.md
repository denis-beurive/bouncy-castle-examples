# Notes on Bouncy Castle

## Use generators

At first, you may, legitimately, think that you create the desired object by calling the associated constructor.
This approach does not work every time. Sometimes, you don't use the constructor (which, by the way is not public),
you use the appropriate generator instead.

* **Sign a document** ? Use a signature generator - `org.bouncycastle.openpgp.PGPSignatureGenerator`.
* **Add subpackets to a signature** ? Use a subpacket generator - `org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator`.
* **Create a pair of RSA keys** ? Use an RSA key pair generator - `org.bouncycastle.crypto.generators.RSAKeyPairGenerator`.
* **Create a pair of DSA keys** ? Use an DSA key pair generator - `org.bouncycastle.crypto.generators.DSAParametersGenerator`.
* **Create a pair of El Gamal key** ? Use an El Gamal key pair generator - `ElGamalKeyPairGenerator`.
* **Create a key ring** ? Use a key ring generator - `org.bouncycastle.openpgp.PGPKeyRingGenerator`.
* **Create a compressed data packet** ? User a compressed data packet generator - `org.bouncycastle.openpgp.PGPCompressedDataGenerator`.
