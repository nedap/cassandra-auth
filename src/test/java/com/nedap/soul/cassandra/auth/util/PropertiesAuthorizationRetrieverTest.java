package com.nedap.soul.cassandra.auth.util;

import com.nedap.soul.cassandra.auth.util.PropertiesAuthorizationRetriever;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map.Entry;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.config.ConfigurationException;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.ExpectedException;

public class PropertiesAuthorizationRetrieverTest {

    @Rule
    public ExpectedException exceptionExpectation = ExpectedException.none();

    private final PropertiesAuthorizationRetriever propertiesRetriever;

    public PropertiesAuthorizationRetrieverTest() {
        propertiesRetriever = new PropertiesAuthorizationRetriever();
        System.setProperty(PropertiesAuthorizationRetriever.AUTHORIZATION_FILENAME_PROPERTY, "src/test/resources/authorization.properties");
    }

    @Test
    public void testGetPermissionMapForNonExistingUser() {
        LinkedHashMap<String, EnumSet<Permission>> permissionMap = propertiesRetriever.getPermissionMapForUser("non_existing_user");
        assertTrue(permissionMap.isEmpty());
    }

    @Test
    public void testGetPermissionMapForExistingUser() {
        LinkedHashMap<String, EnumSet<Permission>> permissionMap = propertiesRetriever.getPermissionMapForUser("username");
        Iterator<Entry<String, EnumSet<Permission>>> iterator = permissionMap.entrySet().iterator();

        assertEquals(permissionMap.size(), 2);
        Entry<String, EnumSet<Permission>> first = iterator.next();

        assertEquals(first.getKey(), "/cassandra/keyspaces/test");
        assertEquals(first.getValue(), EnumSet.of(Permission.ALTER, Permission.CREATE, Permission.READ, Permission.WRITE));
        Entry<String, EnumSet<Permission>> second = iterator.next();

        assertEquals(second.getKey(), "/cassandra/keyspaces/test2");
        assertEquals(second.getValue(), EnumSet.of(Permission.READ));
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
         System.clearProperty(PropertiesAuthorizationRetriever.AUTHORIZATION_FILENAME_PROPERTY);
         propertiesRetriever.validateBackend();
    }

    @Test
    public void testValidateBackendWithoutFile() throws Exception {
         exceptionExpectation.expect(ConfigurationException.class);
         System.setProperty(PropertiesAuthorizationRetriever.AUTHORIZATION_FILENAME_PROPERTY, "non_existing");
         propertiesRetriever.validateBackend();
    }

}