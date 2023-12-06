package com.southernstorm.noise.protocol;

import java.util.Arrays;

import com.southernstorm.noise.crypto.CurveP256;

/**
 * Implementation of the CurveP256 algorithm for the Noise protocol.
 */
class CurveP256DHState implements DHState {

    private byte[] publicKey;
    private byte[] privateKey;
    private int mode;

    /**
     * Constructs a new Diffie-Hellman object for CurveP256.
     */
    public CurveP256DHState()
    {
        publicKey = new byte [33];
        privateKey = new byte [32];
        mode = 0;
    }

    @Override
    public void destroy() {
        clearKey();
    }

    @Override
    public String getDHName() {
        return "P256";
    }

    @Override
    public int getPublicKeyLength() {
        return 33;
    }

    @Override
    public int getPrivateKeyLength() {
        return 32;
    }

    @Override
    public int getSharedKeyLength() {
        return 33;
    }

    @Override
    public void generateKeyPair() {
        Noise.random(privateKey);
        CurveP256.eval(publicKey, 0, privateKey, null);
        mode = 0x03;
    }

    @Override
    public void getPublicKey(byte[] key, int offset) {
        System.arraycopy(publicKey, 0, key, offset, 33);
    }

    @Override
    public void setPublicKey(byte[] key, int offset) {
        System.arraycopy(key, offset, publicKey, 0, 33);
        Arrays.fill(privateKey, (byte)0);
        mode = 0x01;
    }

    @Override
    public void getPrivateKey(byte[] key, int offset) {
        System.arraycopy(privateKey, 0, key, offset, 32);
    }

    @Override
    public void setPrivateKey(byte[] key, int offset) {
        System.arraycopy(key, offset, privateKey, 0, 32);
        CurveP256.eval(publicKey, 0, privateKey, null);
        mode = 0x03;
    }

    @Override
    public void setToNullPublicKey() {
        Arrays.fill(publicKey, (byte)0);
        Arrays.fill(privateKey, (byte)0);
        mode = 0x01;
    }

    @Override
    public void clearKey() {
        Noise.destroy(publicKey);
        Noise.destroy(privateKey);
        mode = 0;
    }

    @Override
    public boolean hasPublicKey() {
        return (mode & 0x01) != 0;
    }

    @Override
    public boolean hasPrivateKey() {
        return (mode & 0x02) != 0;
    }

    @Override
    public boolean isNullPublicKey() {
        if ((mode & 0x01) == 0)
            return false;
        int temp = 0;
        for (int index = 0; index < 33; ++index)
            temp |= publicKey[index];
        return temp == 0;
    }

    @Override
    public void calculate(byte[] sharedKey, int offset, DHState publicDH) {
        if (!(publicDH instanceof CurveP256DHState))
            throw new IllegalArgumentException("Incompatible DH algorithms");
        CurveP256.eval(sharedKey, offset, privateKey, ((CurveP256DHState)publicDH).publicKey);
    }

    @Override
    public void copyFrom(DHState other) {
        if (!(other instanceof CurveP256DHState))
            throw new IllegalStateException("Mismatched DH key objects");
        if (other == this)
            return;
        CurveP256DHState dh = (CurveP256DHState)other;
        System.arraycopy(dh.privateKey, 0, privateKey, 0, 32);
        System.arraycopy(dh.publicKey, 0, publicKey, 0, 33);
        mode = dh.mode;
    }
}
