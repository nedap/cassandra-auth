package com.nedap.soul.cassandra.auth.pbkdf2;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.codec.binary.Hex;

public class PasswordGenerator {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String PRNG      = "SHA1PRNG";
    private static final int defaultIterations       = 65536;
    private static final int defaultDerivedKeyLength = 256;

    public SecretKeyFactory getAlgorithm() {
        return algorithm;
    }

    public int getIterations() {
        return iterations;
    }

    public int getDerivedKeyLength() {
        return derivedKeyLength;
    }

    public byte[] getSalt() {
        return salt;
    }

    private SecretKeyFactory algorithm;
    private int iterations;
    private int derivedKeyLength;
    private byte[] salt;

    public PasswordGenerator(int iterations, int derivedKeyLength, byte[] salt)  throws NoSuchAlgorithmException {
        this.algorithm        = SecretKeyFactory.getInstance(ALGORITHM);
        this.iterations       = iterations;
        this.derivedKeyLength = derivedKeyLength;
        this.salt             = salt;
    }

    public PasswordGenerator() throws NoSuchAlgorithmException {
        this.algorithm        = SecretKeyFactory.getInstance(ALGORITHM);
        this.iterations       = defaultIterations;
        this.derivedKeyLength = defaultDerivedKeyLength;
        this.salt             = generateSalt();
    }

    public String hash(String password) {
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, derivedKeyLength);
            byte[] data = algorithm.generateSecret(spec).getEncoded();
            return "" + iterations + ":" + derivedKeyLength + ":" + Hex.encodeHexString(salt) + ":" + Hex.encodeHexString(data);
        } catch (InvalidKeySpecException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance(PRNG);
        byte[] salt = new byte[8];
        random.nextBytes(salt);
        return salt;
    }

}