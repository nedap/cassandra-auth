package com.nedap.soul.cassandra.auth.util;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.config.ConfigurationException;

public interface AuthorizationRetriever {

    /*
     * Returns an ordered list of authorizations with permission sets.
     * It should be ordered by most specific first.
     */
    public LinkedHashMap<String,EnumSet<Permission>> getPermissionMapForUser(String username);

    public void validateBackend() throws ConfigurationException;

}
