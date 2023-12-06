/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package com.southernstorm.noise.tests;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Test;

import com.southernstorm.noise.crypto.CurveP256;



public class CurveP256Tests {

    @Test
    public void curveP256() {
        // Test vectors
        byte[] alicePrivate = TestUtils.stringToData("0xf09691a3df81425c31d074917ee4dc1f28c8aec5d77fc5e48679b68567465eb4");
        byte[] alicePublic  = TestUtils.stringToData("0x02111973f476816ed6ad905c6487c95c0ba88edf9565b5685b50d0dbedcc70d2d7");
        byte[] bobPrivate   = TestUtils.stringToData("0xcedce462f2928ff403365b250ddfe9f251fa10dd76674c4997081fc6d4d6acf4");
        byte[] bobPublic    = TestUtils.stringToData("0x023135351915c87fb719b0052c188f9e579a2239544b02b91ab43274aee575a76d");
        byte[] sharedSecret = TestUtils.stringToData("0x03d321f47d1b5eac4440cc75ab140480f2d84e717a52c7c8150c27781dd96b52c7");
        byte[] output = new byte [33];

        // Test derivation of public keys from private keys.
        Arrays.fill(output, (byte)0xAA);
        CurveP256.eval(output, 0, alicePrivate, null);
        assertArrayEquals(alicePublic, output);

        Arrays.fill(output, (byte)0xAA);
        CurveP256.eval(output, 0, bobPrivate, null);
        assertArrayEquals(bobPublic, output);

        // Test creation of the shared secret in both directions.
        Arrays.fill(output, (byte)0xAA);
        CurveP256.eval(output, 0, alicePrivate, bobPublic);
        assertArrayEquals(sharedSecret, output);

        Arrays.fill(output, (byte)0xAA);
        CurveP256.eval(output, 0, bobPrivate, alicePublic);
        assertArrayEquals(sharedSecret, output);
    }

}
