package com.nedap.soul.cassandra.auth.authorization;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Properties;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.config.ConfigurationException;
import org.apache.commons.lang.StringUtils;

public class PropertiesAuthorizationBackend implements AuthorizationBackend {

    public static String AUTHORIZATION_FILENAME_PROPERTY = "authorization.properties";

    @Override
    public LinkedHashMap<String, EnumSet<Permission>> getPermissionMapForUser(String username) {
        try {
            Properties authProps = loadAuthorizationFile();
            String line = authProps.getProperty(username);
            return parseEntry(line, false);
        } catch (IOException ex) {
            return null;
        }
    }

    @Override
    public LinkedHashMap<String, EnumSet<Permission>> getGrantMapForUser(String username) {
        try {
            Properties authProps = loadAuthorizationFile();
            String line = authProps.getProperty(username);
            return parseEntry(line, true);
        } catch (IOException ex) {
            return null;
        }
    }

    @Override
    public boolean storePermission(String username, String resource, EnumSet<Permission> permission, EnumSet<Permission> grant) {
        try {
            Properties authProps = loadAuthorizationFile();
            String line = authProps.getProperty(username);
            boolean updated = false;
            List<String> entries = new ArrayList<String>();
            if(line != null) {
                entries = new ArrayList<String>(Arrays.asList(line.split(",")));
                for(int i = 0; i < entries.size(); ++i) {
                    String entry = entries.get(i);
                    String[] parts = entry.split("=");
                    if(parts.length != 2) {
                        throw new RuntimeException("Invalid access control entry: " + entry);
                    }
                    if(parts[0].equals(resource)) {
                        entries.set(i, serializeEntry(resource, permission, grant));
                        updated = true;
                    }
                }
            }

            if(!updated) {
                entries.add(serializeEntry(resource, permission, grant));
            }
            authProps.setProperty(username, StringUtils.join(entries, ","));
            authProps.store(new FileOutputStream(getAuthorizationFilename()), null);
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    @Override
    public void validateBackend() throws ConfigurationException {
        String auth = getAuthorizationFilename();
        if (auth == null) {
            throw new ConfigurationException("When using " + this.getClass().getCanonicalName() + " " +
                    AUTHORIZATION_FILENAME_PROPERTY + " properties must be defined.");
        }

        File authFile = new File(auth);
        if(!authFile.exists()) {
            throw new ConfigurationException("When using " + this.getClass().getCanonicalName() + " " +
                    " given passwd file needs to exist: " + authFile.getAbsolutePath());
        }
    }

    private Properties loadAuthorizationFile() throws IOException {
        Properties props = new Properties();
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(getAuthorizationFilename()));
        props.load(in);
        in.close();
        return props;
    }

    private String getAuthorizationFilename() {
        return System.getProperty(AUTHORIZATION_FILENAME_PROPERTY);
    }

    private LinkedHashMap<String, EnumSet<Permission>> parseEntry(String line, boolean grants) {
        if(line == null) {
            return new LinkedHashMap<String, EnumSet<Permission>>();
        }
        LinkedHashMap<String, EnumSet<Permission>> result = new LinkedHashMap<String, EnumSet<Permission>>();
        String[] entries = line.split(",");
        for(String entry : entries) {
            String[] parts = entry.split("=");
            if(parts.length != 2) {
                throw new RuntimeException("Invalid access control entry: " + entry);
            }
            EnumSet<Permission> permissionSet = EnumSet.noneOf(Permission.class);
            for(String permission : parts[1].split("\\|")) {
                if(grants) {
                    if(permission.endsWith("+")) {
                        permission = permission.replace("+", "");
                        permissionSet.add(Permission.valueOf(permission));
                    }
                } else {
                    if(permission.endsWith("+")) {
                        permission = permission.replace("+", "");
                    }
                    permissionSet.add(Permission.valueOf(permission));
                }
            }
            result.put(parts[0], EnumSet.copyOf(permissionSet));
        }
        return result;
    }

    private String serializeEntry(String resource, EnumSet<Permission> permission, EnumSet<Permission> grant) {
        ArrayList<String> parts = new ArrayList<String>(permission.size());
        for(Permission perm: permission) {
            String permStr = perm.toString();
            if(grant.contains(perm)) {
                permStr += "+";
            }
            parts.add(permStr);
        }
        return resource + "=" + StringUtils.join(parts, "|");
    }

}