package com.beurive;

import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;

/**
 * This class contains the main elements of a One Pass Signature Packet.
 *
 * ┌───────────────────────────────────┐
 * │ One Pass Signature Packet (tag=4) │
 * └───────────────────────────────────┘
 * ┌───────────────────────────────────┐
 * │ Signature Packet (tag=2)          │
 * └───────────────────────────────────┘
 */

public class OnePassSignatureData {
    PGPOnePassSignature onePassSignaturePacket;
    PGPSignatureGenerator signerGenerator;

    public OnePassSignatureData(
            PGPOnePassSignature inOnePassSignaturePacket,
            PGPSignatureGenerator inSignerGenerator) {
        this.onePassSignaturePacket = inOnePassSignaturePacket;
        this.signerGenerator = inSignerGenerator;
    }

    public PGPOnePassSignature getOnePassSignaturePacket() {
        return this.onePassSignaturePacket;
    }

    public PGPSignatureGenerator getSignerGenerator() {
        return this.signerGenerator;
    }
}
