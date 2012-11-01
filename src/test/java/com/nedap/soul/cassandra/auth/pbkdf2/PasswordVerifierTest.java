package com.nedap.soul.cassandra.auth.pbkdf2;

import org.junit.Test;
import static org.junit.Assert.*;

public class PasswordVerifierTest {

    @Test
    public void testVerify() throws Exception {
        PasswordVerifier instance = new PasswordVerifier("65536:256:66697865645f73616c74:a7da14d5955d903dfba9f6bc0ba403e518e27f66364080e4d16e5fcf72fe8983");
        assertTrue(instance.verify("password".toCharArray()));
        assertFalse(instance.verify("password1".toCharArray()));
    }
}