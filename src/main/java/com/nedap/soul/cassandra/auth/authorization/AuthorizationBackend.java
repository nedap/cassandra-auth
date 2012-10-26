package com.nedap.soul.cassandra.auth.authorization;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.config.ConfigurationException;

public interface AuthorizationBackend {

    /*
     * Returns an ordered list of authorizations with permission sets.
     * It should be ordered by most specific first.
     */
    public LinkedHashMap<String,EnumSet<Permission>> getPermissionMapForUser(String username);

    /*
     * Whether a user is granted access to grant a permission to the given resource
     */
    public LinkedHashMap<String,EnumSet<Permission>> getGrantMapForUser(String username);

    /*
     * Store new permissions for a resource for a user
     */
    public boolean storePermission(String username, String resource, EnumSet<Permission> permission, EnumSet<Permission> grant);

    public void validateBackend() throws ConfigurationException;

}
