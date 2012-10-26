package com.nedap.soul.cassandra.auth;

import com.nedap.soul.cassandra.auth.authorization.AuthorizationBackend;
import com.nedap.soul.cassandra.auth.authorization.CassandraAuthorizationBackend;
import java.util.ArrayList;
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
import org.apache.cassandra.thrift.Column;
import org.apache.cassandra.thrift.CqlResult;
import org.apache.cassandra.thrift.CqlRow;
import org.apache.cassandra.thrift.InvalidRequestException;
import org.apache.cassandra.utils.ByteBufferUtil;

public class Authorizer implements IAuthority2 {

    private final AuthorizationBackend retriever;

    public Authorizer() {
        this.retriever = new CassandraAuthorizationBackend();
    }

    public Authorizer(AuthorizationBackend retriever) {
        this.retriever = retriever;
    }

    @Override
    public EnumSet<Permission> authorize(AuthenticatedUser user, List<Object> resource) {
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
        if(hasGrant(granter.username, resourceList(resource), permission)) {
            LinkedHashMap<String, EnumSet<Permission>> permissionMapForUser = retriever.getPermissionMapForUser(to);
            LinkedHashMap<String, EnumSet<Permission>> grantMapForUser      = retriever.getGrantMapForUser(to);
            String resourceString = resourceString(resource);
            boolean stored = false;
            for(Map.Entry<String, EnumSet<Permission>> entry : permissionMapForUser.entrySet()) {
                if(resourceString.equals(entry.getKey())) {
                    EnumSet<Permission> perms = entry.getValue();
                    EnumSet<Permission> grants = grantMapForUser.get(entry.getKey());
                    stored = addPermission(to, resourceString, permission, grantOption, perms, grants);
                }
            }
            if(!stored) {
                EnumSet<Permission> perms  = EnumSet.noneOf(Permission.class);
                EnumSet<Permission> grants = EnumSet.noneOf(Permission.class);
                stored = addPermission(to, resourceString, permission, grantOption, perms, grants);
            }
            if(!stored) {
                throw new InvalidRequestException("Failed to store permissions");
            }
        } else {
            throw new InvalidRequestException("User " + granter.username + " cannot grant permission " + permission + " to " + resource);
        }
    }

    @Override
    public void revoke(AuthenticatedUser revoker, Permission permission, String from, CFName resource) throws InvalidRequestException {
        if(hasGrant(revoker.username, resourceList(resource), permission)) {
            LinkedHashMap<String, EnumSet<Permission>> permissionMapForUser = retriever.getPermissionMapForUser(from);
            LinkedHashMap<String, EnumSet<Permission>> grantMapForUser      = retriever.getGrantMapForUser(from);
            String resourceString = resourceString(resource);
            for(Map.Entry<String, EnumSet<Permission>> entry : permissionMapForUser.entrySet()) {
                if(resourceString.equals(entry.getKey())) {
                    EnumSet<Permission> perms = entry.getValue();
                    EnumSet<Permission> grants = grantMapForUser.get(entry.getKey());
                    if(!removePermission(from, resourceString, permission, perms, grants)) {
                        throw new InvalidRequestException("Failed to remove permission");
                    }
                }
            }
        } else {
            throw new InvalidRequestException("User " + revoker.username + " cannot revoke permission " + permission + " to " + resource);
        }
    }

    @Override
    public CqlResult listPermissions(String username) throws InvalidRequestException {
        CqlResult result = new CqlResult();

        LinkedHashMap<String, EnumSet<Permission>> permissionMapForUser = retriever.getPermissionMapForUser(username);
        LinkedHashMap<String, EnumSet<Permission>> grantMapForUser = retriever.getGrantMapForUser(username);

        for(Map.Entry<String, EnumSet<Permission>> entry : permissionMapForUser.entrySet()) {
            CqlRow row      = new CqlRow();
            Column colPerm  = new Column(ByteBufferUtil.bytes("permissions"));
            Column colGrant = new Column(ByteBufferUtil.bytes("grants"));

            EnumSet<Permission> grants = grantMapForUser.get(entry.getKey());
            row.key = ByteBufferUtil.bytes(entry.getKey());
            colPerm.value = ByteBufferUtil.bytes(entry.getValue().toString());
            colGrant.value = ByteBufferUtil.bytes(grants.toString());
            row.addToColumns(colPerm);
            row.addToColumns(colGrant);
            result.addToRows(row);
            result.num++;
        }
        return result;
    }

    @Override
    public void validateConfiguration() throws ConfigurationException {
        retriever.validateBackend();
    }

    private boolean hasGrant(String user, List<Object> resource, Permission perm) {
        LinkedHashMap<String, EnumSet<Permission>> grantMapForUser = retriever.getGrantMapForUser(user);
        for(Map.Entry<String, EnumSet<Permission>> entry : grantMapForUser.entrySet()) {
            if(matchResource(resource, entry.getKey())) {
                return entry.getValue().contains(perm);
            }
        }

        return false;
    }

    private boolean addPermission(String to, String resource, Permission permission, boolean grantOption,
                                    EnumSet<Permission> perms, EnumSet<Permission> grants) {
        perms.add(permission);
        if(grantOption) {
            grants.add(permission);
        }
        return retriever.storePermission(to, resource, perms, grants);
    }

    private boolean removePermission(String to, String resource, Permission permission,
                                    EnumSet<Permission> perms, EnumSet<Permission> grants) {
        perms.remove(permission);
        grants.remove(permission);
        return retriever.storePermission(to, resource, perms, grants);
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

    private List<Object> resourceList(CFName resource) {
        List<Object> result = new ArrayList<Object>();
        result.add(Resources.ROOT);
        result.add(Resources.KEYSPACES);
        if(resource.hasKeyspace()) {
            result.add(resource.getKeyspace());
            result.add(resource.getColumnFamily());
        }
        return result;
    }

    private String resourceString(CFName resource) {
        StringBuilder builder = new StringBuilder();
        builder.append("/");
        builder.append(Resources.ROOT);
        builder.append("/");
        builder.append(Resources.KEYSPACES);
        if(resource.hasKeyspace()) {
            builder.append("/");
            builder.append(resource.getKeyspace());
            if(resource.getColumnFamily() != null) {
                builder.append("/");
                builder.append(resource.getColumnFamily());
            }
        }
        return builder.toString();
    }

}