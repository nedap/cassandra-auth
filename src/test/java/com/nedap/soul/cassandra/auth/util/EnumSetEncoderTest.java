package com.nedap.soul.cassandra.auth.util;

import java.util.EnumSet;
import org.apache.cassandra.auth.Permission;
import org.junit.Test;
import static org.junit.Assert.*;

public class EnumSetEncoderTest {

    private EnumSetEncoder<Permission> encoder;

    public EnumSetEncoderTest() {
        encoder = new EnumSetEncoder<Permission>(Permission.class);
    }

    @Test
    public void testEncode() {
        EnumSet<Permission> perms = EnumSet.noneOf(Permission.class);
        perms.add(Permission.READ);
        perms.add(Permission.WRITE);
        assertEquals(3, encoder.encode(perms));
    }

    @Test
    public void testDecode() {
        EnumSet<Permission> perms = EnumSet.noneOf(Permission.class);
        perms.add(Permission.READ);
        perms.add(Permission.WRITE);
        assertEquals(perms, encoder.decode(1571));
    }

}
