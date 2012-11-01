/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package com.nedap.soul.cassandra.auth.pbkdf2;

public class Hex {

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    public static String encodeHexString(byte[] data) {
        char[] out = new char[data.length * 2];
        for(int i = 0; i < data.length; ++i) {
            byte b            = data[i];
            int char_pos      = i * 2;
            out[char_pos]     = HEX_CHARS[(b & 0xF0) >> 4 ];
            out[char_pos + 1] = HEX_CHARS[b & 0x0F];
        }
        return new String(out);
    }

    public static byte[] decodeHexString(String str) {
        byte[] out = new byte[str.length() / 2];
        char[] data = str.toCharArray();
        for(int i = 0; i < out.length; ++i) {
            int char_pos      = i * 2;
            int c = Character.digit(data[char_pos], 16) << 4;
            c    |= Character.digit(data[char_pos + 1], 16);
            out[i] = (byte) (c & 0xFF);
        }
        return out;
    }

}
