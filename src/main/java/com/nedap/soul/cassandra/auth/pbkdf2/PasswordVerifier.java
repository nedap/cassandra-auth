package com.nedap.soul.cassandra.auth.pbkdf2;

import java.security.NoSuchAlgorithmException;
import org.apache.cassandra.utils.Hex;

public class PasswordVerifier {

    private PasswordGenerator generator;
    private String encoded;

    public PasswordVerifier(String encoded) throws NoSuchAlgorithmException {
        this.encoded = encoded;
        String[] parts = encoded.split(":");
        if(parts.length != 4) {
            throw new IllegalArgumentException("String can't be decoded for verification");
        }
        int iterations       = Integer.parseInt(parts[0]);
        int derivedKeyLength = Integer.parseInt(parts[1]);
        byte[] salt          = Hex.hexToBytes(parts[2]);
        generator            = new PasswordGenerator(iterations, derivedKeyLength, salt);
    }

    public boolean verify(String password) {
        return generator.hash(password).equals(encoded);
    }
}