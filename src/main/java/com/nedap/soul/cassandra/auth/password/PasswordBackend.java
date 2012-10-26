package com.nedap.soul.cassandra.auth.password;

import org.apache.cassandra.config.ConfigurationException;

public interface PasswordBackend {

    public String getPasswordHashForUser(String username, String field);

    public void validateBackend() throws ConfigurationException;

}