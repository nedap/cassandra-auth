package com.nedap.soul.cassandra.auth;

import com.nedap.soul.cassandra.auth.password.CassandraPasswordBackend;
import com.nedap.soul.cassandra.auth.password.PasswordBackend;
import com.nedap.soul.cassandra.auth.pbkdf2.PasswordVerifier;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.config.ConfigurationException;
import org.apache.cassandra.thrift.AuthenticationException;

public class Authenticator implements IAuthenticator {

    private final PasswordBackend retriever;

    public Authenticator() {
        this.retriever = new CassandraPasswordBackend();
    }

    public Authenticator(PasswordBackend retriever) {
        this.retriever = retriever;
    }

    @Override
    public AuthenticatedUser defaultUser() {
        return null;
    }

    @Override
    public AuthenticatedUser authenticate(Map<? extends CharSequence, ? extends CharSequence> credentials) throws AuthenticationException {
        String givenUsername = getKey(credentials, USERNAME_KEY).toString();
        String givenPassword = getKey(credentials, PASSWORD_KEY).toString();

        String storedHash = retriever.getPasswordHashForUser(givenUsername, PASSWORD_KEY);
        if(storedHash == null) {
              throw new AuthenticationException(errorMessage(givenUsername));
        }
        try {
            PasswordVerifier verifier = new PasswordVerifier(storedHash);
            if(verifier.verify(givenPassword)) {
                return new AuthenticatedUser(givenUsername);
            }
            throw new AuthenticationException(errorMessage(givenUsername));
        } catch (NoSuchAlgorithmException ex) {
            throw new AuthenticationException("Unknown algorithm: " + ex.getMessage());
        }
    }

    @Override
    public void validateConfiguration() throws ConfigurationException {
        retriever.validateBackend();
    }

    private CharSequence getKey(Map<? extends CharSequence, ? extends CharSequence> credentials, String key) throws AuthenticationException {
        CharSequence value = credentials.get(key);
        if(value == null) {
            throw new AuthenticationException("No " + key + " provided");
        }
        return value;
    }

    private String errorMessage(String username) {
        return String.format("Given password could not be validated for user %s", username);
    }
}