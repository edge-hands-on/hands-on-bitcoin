/*
 * Copyright 2018 Coinomi Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.bitcoinhandson;

/**
 * Based on the code in: https://github.com/ValleZ/Paper-Wallet/blob/master/app/src/main/java/ru/valle/btc/Bech32.java
 */

import java.io.ByteArrayOutputStream;

final class Bech32 {
    private static final String charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] generator = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

    public static String encodeAddress(String hrp, int version, byte[] pubKeyData) {
        byte[] data = convertBits(pubKeyData, 8, 5, true);
        byte[] versionPlusData = new byte[1 + data.length];
        versionPlusData[0] = (byte) version;
        System.arraycopy(data, 0, versionPlusData, 1, data.length);
        return encode(hrp, versionPlusData);
    }

    public static byte[] decodeAddress(String hrp, String address) {
        DecodeResult decoded = decode(address);
        String dechrp = decoded.dechrp;
        byte[] data = decoded.data;

        if (!dechrp.equals(hrp)) {
            throw new RuntimeException("invalid human-readable part: " + hrp + " != " + dechrp);
        }

        if (data.length == 0) {
            throw new RuntimeException("invalid decode data length: " + data.length);
        }

        if ((data[0] & 0xff) > 16) {
            throw new RuntimeException("invalid witness version: " + (data[0] & 0xff));
        }

        byte[] dataWithNoVersion = new byte[data.length - 1];
        System.arraycopy(data, 1, dataWithNoVersion, 0, dataWithNoVersion.length);

        byte[] res = convertBits(dataWithNoVersion, 5, 8, false);

        if (res.length < 2 || res.length > 40) {
            throw new RuntimeException("invalid convertbits length: " + res.length);
        }


        if (data[0] == 0 && res.length != 20 && res.length != 32) {
            throw new RuntimeException("invalid program length for witness version 0 (per BIP141): " + res.length);
        }

        return res;
    }

    static class DecodeResult {
        final String dechrp;
        final byte[] data;

        DecodeResult(String dechrp, byte[] data) {
            this.dechrp = dechrp;
            this.data = data;
        }
    }

    static DecodeResult decode(String bechString) {
        if (bechString.length() > 90) {
            throw new RuntimeException("too long: len=" + bechString.length());
        }

        int pos = bechString.lastIndexOf('1');
        if (pos < 1 || pos + 7 > bechString.length()) {
            throw new RuntimeException("separator '1' at invalid position: pos=" + pos + ", len=" + bechString.length());
        }

        String hrp = bechString.substring(0, pos);

        byte[] data = new byte[bechString.length() - pos - 1];
        for (int p = pos + 1, i = 0; p < bechString.length(); p++, i++) {
            int d = charset.indexOf(bechString.charAt(p));
            if (d == -1) {
                throw new RuntimeException("invalid character data part : bechString[" + p + "]=" + bechString.charAt(p));
            }
            data[i] = (byte) d;
        }

        if (!verifyChecksum(hrp, data)) {
            throw new RuntimeException("invalid checksum");
        }

        byte[] outData = new byte[data.length - 6];
        System.arraycopy(data, 0, outData, 0, outData.length);

        return new DecodeResult(hrp, outData);
    }

    private static boolean verifyChecksum(String hrp, byte[] data) {
        byte[] ehrp = hrpExpand(hrp);
        byte[] values = new byte[ehrp.length + data.length];

        System.arraycopy(ehrp, 0, values, 0, ehrp.length);
        System.arraycopy(data, 0, values, ehrp.length, data.length);

        return polymod(values) == 1;
    }

    static String encode(String hrp, byte[] data) {
        byte[] checksum = createChecksum(hrp, data);
        byte[] combined = new byte[data.length + checksum.length];

        System.arraycopy(data, 0, combined, 0, data.length);
        System.arraycopy(checksum, 0, combined, data.length, checksum.length);

        StringBuilder ret = new StringBuilder();
        ret.append(hrp);
        ret.append("1");
        for (byte b : combined) {
            int p = b & 0xff;
            ret.append(charset.charAt(p));
        }

        return ret.toString();
    }

    private static byte[] createChecksum(String hrp, byte[] data) {
        byte[] ehrp = hrpExpand(hrp);
        byte[] values = new byte[ehrp.length + data.length + 6];

        System.arraycopy(ehrp, 0, values, 0, ehrp.length);
        System.arraycopy(data, 0, values, ehrp.length, data.length);
        int mod = polymod(values) ^ 1;

        byte[] ret = new byte[6];
        for (int p = 0; p < ret.length; p++) {
            ret[p] = (byte) ((mod >>> (5 * (5 - p))) & 31);
        }

        return ret;
    }

    private static int polymod(byte[] values) {
        int chk = 1;
        for (byte value : values) {
            int v = value & 0xff;
            int top = chk >>> 25;
            chk = (chk & 0x1ffffff) << 5 ^ v;
            for (int j = 0; j < 5; j++) {
                if (((top >> j) & 1) == 1) {
                    chk ^= generator[j];
                }
            }
        }

        return chk;
    }

    private static byte[] hrpExpand(String hrp) {
        byte[] ret = new byte[hrp.length() * 2 + 1];

        for (int i = 0; i < hrp.length(); i++) {
            char c = hrp.charAt(i);
            ret[i] = (byte) (c >> 5);
        }

        for (int i = 0; i < hrp.length(); i++) {
            char c = hrp.charAt(i);
            ret[i + hrp.length() + 1] = (byte) (c & 31);
        }

        return ret;
    }

    private static byte[] convertBits(byte[] data, int frombits, int tobits, boolean pad) {
        int acc = 0;
        int bits = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        int maxv = (1 << tobits) - 1;
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xff;
            if ((value >>> frombits) != 0) {
                throw new RuntimeException("invalid data range: data[" + i + "]=" + value + " (frombits=" + frombits + ")");
            }
            acc = (acc << frombits) | value;
            bits += frombits;
            while (bits >= tobits) {
                bits -= tobits;
                baos.write((acc >>> bits) & maxv);
            }
        }

        if (pad) {
            if (bits > 0) {
                baos.write((acc << (tobits - bits)) & maxv);
            }
        } else if (bits >= frombits) {
            throw new RuntimeException( "illegal zero padding");
        } else if (((acc << (tobits - bits)) & maxv) != 0) {
            throw new RuntimeException( "non-zero padding");
        }

        return baos.toByteArray();
    }
}
