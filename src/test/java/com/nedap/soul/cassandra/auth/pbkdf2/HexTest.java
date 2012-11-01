package com.nedap.soul.cassandra.auth.pbkdf2;

import org.junit.Test;
import static org.junit.Assert.*;

public class HexTest {

    @Test
    public void testEncodeHexString() {
        byte[] data = new byte[]{(byte)0xFF, (byte)0x10};
        assertEquals("ff10", Hex.encodeHexString(data));
    }

    @Test
    public void testDecodeHexString() {
        byte[] data = new byte[]{(byte)0xFF, (byte)0x10};
        assertArrayEquals(data, Hex.decodeHexString("ff10"));
    }
}
