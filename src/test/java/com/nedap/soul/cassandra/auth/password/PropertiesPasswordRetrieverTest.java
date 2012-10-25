package com.nedap.soul.cassandra.auth.password;

import org.apache.cassandra.config.ConfigurationException;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.ExpectedException;

public class PropertiesPasswordRetrieverTest {

    @Rule
    public ExpectedException exceptionExpectation = ExpectedException.none();

    private final PropertiesPasswordRetriever propertiesRetriever;

    public PropertiesPasswordRetrieverTest() {
        propertiesRetriever = new PropertiesPasswordRetriever();
        System.setProperty(PropertiesPasswordRetriever.PASSWD_FILENAME_PROPERTY, "src/test/resources/passwd.properties");
    }

    @Test
    public void testGetPasswordHashForExistingUser() {
        String result = propertiesRetriever.getPasswordHashForUser("username", "password");
        assertEquals("65536:256:66697865645f73616c74:a7da14d5955d903dfba9f6bc0ba403e518e27f66364080e4d16e5fcf72fe8983", result);
    }

    @Test
    public void testGetPasswordHashForNonExistingUser() {
        String result = propertiesRetriever.getPasswordHashForUser("non_existing_username", "password");
        assertNull(result);
    }

    @Test
    public void testValidateBackendWithFile() throws Exception {
        try {
            propertiesRetriever.validateBackend();
        } catch(Exception e) {
            fail("No exception should be raised: " + e.getMessage());
        }
    }

    @Test
    public void testValidateBackendWithoutProperty() throws Exception {
         exceptionExpectation.expect(ConfigurationException.class);
         System.clearProperty(PropertiesPasswordRetriever.PASSWD_FILENAME_PROPERTY);
         propertiesRetriever.validateBackend();
    }

    @Test
    public void testValidateBackendWithoutFile() throws Exception {
         exceptionExpectation.expect(ConfigurationException.class);
         System.setProperty(PropertiesPasswordRetriever.PASSWD_FILENAME_PROPERTY, "non_existing");
         propertiesRetriever.validateBackend();
    }
}