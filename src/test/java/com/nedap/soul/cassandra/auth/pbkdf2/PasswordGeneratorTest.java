package com.nedap.soul.cassandra.auth.pbkdf2;

import org.junit.Test;
import static org.junit.Assert.*;

public class PasswordGeneratorTest {

    @Test
    public void testHashWithNoArguments() throws Exception {
        PasswordGenerator instance = new PasswordGenerator();
        String result = instance.hash("password".toCharArray());
        assertNotNull(result);
    }

    @Test
    public void testHashWithExplicitArguments() throws Exception {
        PasswordGenerator instance = new PasswordGenerator(10000, 100, "fixed_salt".getBytes());
        String result = instance.hash("password".toCharArray());
        assertEquals("10000:100:66697865645f73616c74:632c613ee241284d50c41efd", result);
    }

    @Test
    public void testGenerateSaltWithDefaultAlgorithm() throws Exception {
        byte[] data = PasswordGenerator.generateSalt();
        assertEquals(8, data.length);
    }

}