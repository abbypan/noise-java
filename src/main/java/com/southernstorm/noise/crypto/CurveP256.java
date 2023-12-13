package com.southernstorm.noise.crypto;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.HexFormat;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.spec.*;

/**
 * Implementation of the CurveP256 elliptic curve algorithm.
 * Nist P-256 
 */
public final class CurveP256 {

    public static void eval(byte[] result, int offset, byte[] priv, byte[] pub) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            BigInteger privBN = new BigInteger(HexFormat.of().formatHex(priv), 16);
            ECNamedCurveParameterSpec  ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECPoint res=null;

            if(pub != null){
                ECCurve curve = ecSpec.getCurve();
                ECPoint p = curve.decodePoint(pub);
                res = p.multiply(privBN);
            }else{
                res = ecSpec.getG().multiply(privBN);
            }

            byte[] compressed = res.getEncoded(true);
            System.arraycopy(compressed, 0, result, offset, compressed.length);

        }catch(Exception e){
        }


        return ;
    }
}
