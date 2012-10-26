package com.nedap.soul.cassandra.auth;

import com.nedap.soul.cassandra.auth.password.PropertiesPasswordBackend;
import java.util.HashMap;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.config.ConfigurationException;
import org.apache.cassandra.thrift.AuthenticationException;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.ExpectedException;

public class AuthenticatorTest {

    private Authenticator propertiesAuthenticator;

    @Rule
    public ExpectedException exceptionExpectation = ExpectedException.none();

    public AuthenticatorTest() throws Exception {
        System.setProperty(PropertiesPasswordBackend.PASSWD_FILENAME_PROPERTY, "src/test/resources/passwd.properties");
        propertiesAuthenticator = new Authenticator(new PropertiesPasswordBackend());
    }

    @Test
    public void testDefaultUser() {
        assertNull(propertiesAuthenticator.defaultUser());
    }

    @Test
    public void testAuthenticateForEmptyPropertyCredentials() throws Exception {
        exceptionExpectation.expect(AuthenticationException.class);
        propertiesAuthenticator.authenticate(new HashMap<CharSequence, CharSequence>());
    }

    @Test
    public void testAuthenticateForNoUsername() throws Exception {
        exceptionExpectation.expect(AuthenticationException.class);

        HashMap<CharSequence, CharSequence> credentials = new HashMap<CharSequence, CharSequence>();
        credentials.put(IAuthenticator.PASSWORD_KEY, "password");
        propertiesAuthenticator.authenticate(credentials);
    }

    @Test
    public void testAuthenticateForNoPassword() throws Exception {
        exceptionExpectation.expect(AuthenticationException.class);

        HashMap<CharSequence, CharSequence> credentials = new HashMap<CharSequence, CharSequence>();
        credentials.put(IAuthenticator.USERNAME_KEY, "username");
        propertiesAuthenticator.authenticate(credentials);
    }

    @Test
    public void testAuthenticateForNonExistingUser() throws Exception {
        exceptionExpectation.expect(AuthenticationException.class);

        HashMap<CharSequence, CharSequence> credentials = new HashMap<CharSequence, CharSequence>();
        credentials.put(IAuthenticator.USERNAME_KEY, "non_existing_username");
        credentials.put(IAuthenticator.PASSWORD_KEY, "password");
        propertiesAuthenticator.authenticate(credentials);
    }

    @Test
    public void testAuthenticateForExistingUserWithWrongPassword() throws Exception {
        exceptionExpectation.expect(AuthenticationException.class);

        HashMap<CharSequence, CharSequence> credentials = new HashMap<CharSequence, CharSequence>();
        credentials.put(IAuthenticator.USERNAME_KEY, "username");
        credentials.put(IAuthenticator.PASSWORD_KEY, "wrong_password");
        propertiesAuthenticator.authenticate(credentials);
    }

    @Test
    public void testAuthenticateForExistingUserWithCorrectPassword() throws Exception {
        HashMap<CharSequence, CharSequence> credentials = new HashMap<CharSequence, CharSequence>();
        credentials.put(IAuthenticator.USERNAME_KEY, "username");
        credentials.put(IAuthenticator.PASSWORD_KEY, "password");
        assertNotNull(propertiesAuthenticator.authenticate(credentials));
    }

    @Test
    public void testValidateConfigurationWithInvalidConfiguration() throws Exception {
        exceptionExpectation.expect(ConfigurationException.class);

        System.setProperty(PropertiesPasswordBackend.PASSWD_FILENAME_PROPERTY, "non_existing");
        propertiesAuthenticator.validateConfiguration();
    }

    @Test
    public void testValidateConfigurationWithValidConfiguration() throws Exception {
        try {
            propertiesAuthenticator.validateConfiguration();
        } catch (ConfigurationException e) {
            fail("configuration exception thrown: "+ e.getMessage());
        }
    }

}