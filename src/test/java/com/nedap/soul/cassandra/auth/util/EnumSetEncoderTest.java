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
        perms.add(Permission.CREATE);
        perms.add(Permission.DELETE);
        perms.add(Permission.SELECT);
        assertEquals(1568, encoder.encode(perms));
    }

    @Test
    public void testDecode() {
        EnumSet<Permission> perms = EnumSet.noneOf(Permission.class);
        perms.add(Permission.CREATE);
        perms.add(Permission.DELETE);
        perms.add(Permission.SELECT);
        assertEquals(perms, encoder.decode(1568));
    }

}
