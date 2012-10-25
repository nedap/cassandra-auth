package com.nedap.soul.cassandra.auth.util;

import java.util.EnumSet;
import org.apache.cassandra.auth.Permission;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author dirkjan
 */
public class EnumSetEncoderTest {

    private EnumSetEncoder<Permission> encoder;

    public EnumSetEncoderTest() {
        encoder = new EnumSetEncoder<Permission>(Permission.class);
    }

    @Test
    public void testEncodeLong() {
        EnumSet<Permission> perms = EnumSet.noneOf(Permission.class);
        perms.add(Permission.CREATE);
        perms.add(Permission.DELETE);
        perms.add(Permission.SELECT);
        assertEquals(1568L, encoder.encodeLong(perms));
    }

    @Test
    public void testDecodeLong() {
        EnumSet<Permission> perms = EnumSet.noneOf(Permission.class);
        perms.add(Permission.CREATE);
        perms.add(Permission.DELETE);
        perms.add(Permission.SELECT);
        assertEquals(perms, encoder.decodeLong(1568L));
    }

}
