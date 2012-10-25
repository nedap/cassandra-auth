package com.nedap.soul.cassandra.auth.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Properties;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.config.ConfigurationException;

public class PropertiesAuthorizationRetriever implements AuthorizationRetriever {

    public static String AUTHORIZATION_FILENAME_PROPERTY = "authorization.properties";

    @Override
    public LinkedHashMap<String, EnumSet<Permission>> getPermissionMapForUser(String username) {
        try {
            Properties authProps = loadAuthorizationFile();
            String line = authProps.getProperty(username);
            return parseEntry(line);
        } catch (IOException ex) {
            return null;
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

    private LinkedHashMap<String, EnumSet<Permission>> parseEntry(String line) {
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
                permissionSet.add(Permission.valueOf(permission));
            }
            result.put(parts[0], EnumSet.copyOf(permissionSet));
        }
        return result;
    }
}