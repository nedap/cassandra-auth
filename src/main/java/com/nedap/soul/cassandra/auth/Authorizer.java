package com.nedap.soul.cassandra.auth;

import com.nedap.soul.cassandra.auth.util.AuthorizationRetriever;
import com.nedap.soul.cassandra.auth.util.CassandraAuthorizationRetriever;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthority2;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.Resources;
import org.apache.cassandra.config.ConfigurationException;
import org.apache.cassandra.cql3.CFName;
import org.apache.cassandra.thrift.CqlResult;
import org.apache.cassandra.thrift.InvalidRequestException;

public class Authorizer implements IAuthority2 {

    private final AuthorizationRetriever retriever;

    public Authorizer() {
        this.retriever = new CassandraAuthorizationRetriever();
    }

    public Authorizer(AuthorizationRetriever retriever) {
        this.retriever = retriever;
    }

    @Override
    public EnumSet<Permission> authorize(AuthenticatedUser user, List<Object> resource) {
        if(user == null) {
            return Permission.NONE;
        }

        if (resource.size() < 2 ||
            !Resources.ROOT.equals(resource.get(0)) ||
            !Resources.KEYSPACES.equals(resource.get(1))) {
            return Permission.NONE;
        }

        LinkedHashMap<String, EnumSet<Permission>> permissionMapForUser = retriever.getPermissionMapForUser(user.username);

        for(Map.Entry<String, EnumSet<Permission>> entry : permissionMapForUser.entrySet()) {
            if(matchResource(resource, entry.getKey())) {
                return entry.getValue();
            }
        }

        return Permission.NONE;
    }

    @Override
    public void setup() {
    }

    @Override
    public void grant(AuthenticatedUser granter, Permission permission, String to, CFName resource, boolean grantOption) throws InvalidRequestException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void revoke(AuthenticatedUser revoker, Permission permission, String from, CFName resource) throws InvalidRequestException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public CqlResult listPermissions(String username) throws InvalidRequestException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void validateConfiguration() throws ConfigurationException {
        retriever.validateBackend();
    }

    private boolean matchResource(List<Object> resource, String entry) {
        // Start with offset 1 because resource paths begin with a /
        String[] parts = entry.split("/");
        if(parts.length - 1 > resource.size()) {
            return false;
        }
        for(int i = 0; i < parts.length - 1; ++i) {
            if(!parts[i + 1].equals(resource.get(i))) {
                return false;
            }
        }
        return true;
    }
}