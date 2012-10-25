package com.nedap.soul.cassandra.auth.password;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import org.apache.cassandra.config.ConfigurationException;

public class PropertiesPasswordRetriever implements PasswordRetriever {

    public static String PASSWD_FILENAME_PROPERTY = "passwd.properties";

    @Override
    public String getPasswordHashForUser(String username, String field) {
        try {
            Properties passwdProps = loadPasswdFile();
            return passwdProps.getProperty(username);
        } catch (IOException ex) {
            return null;
        }
    }

    @Override
    public void validateBackend() throws ConfigurationException {
        String passwd = getPasswdFilename();
        if (passwd == null) {
            throw new ConfigurationException("When using " + this.getClass().getCanonicalName() + " " +
                    PASSWD_FILENAME_PROPERTY + " properties must be defined.");
        }

        File passwdFile = new File(passwd);
        if(!passwdFile.exists()) {
            throw new ConfigurationException("When using " + this.getClass().getCanonicalName() + " " +
                    " given passwd file needs to exist: " + passwdFile.getAbsolutePath());
        }
    }

    private Properties loadPasswdFile() throws IOException {
        Properties props = new Properties();
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(getPasswdFilename()));
        props.load(in);
        in.close();
        return props;
    }

    private String getPasswdFilename() {
        return System.getProperty(PASSWD_FILENAME_PROPERTY);
    }

}