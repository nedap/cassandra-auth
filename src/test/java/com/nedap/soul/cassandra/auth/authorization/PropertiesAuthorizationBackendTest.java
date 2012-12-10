package com.nedap.soul.cassandra.auth.authorization;

import com.nedap.soul.cassandra.auth.AuthorizerTest;
import java.io.File;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.config.ConfigurationException;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.ExpectedException;

public class PropertiesAuthorizationBackendTest {

    @Rule
    public ExpectedException exceptionExpectation = ExpectedException.none();

    private final PropertiesAuthorizationBackend propertiesRetriever;

    public PropertiesAuthorizationBackendTest() {
        propertiesRetriever = new PropertiesAuthorizationBackend();
        System.setProperty(PropertiesAuthorizationBackend.AUTHORIZATION_FILENAME_PROPERTY, "src/test/resources/authorization.properties");
    }

    @Test
    public void testGetPermissionMapForNonExistingUser() {
        LinkedHashMap<String, EnumSet<Permission>> permissionMap = propertiesRetriever.getPermissionMapForUser("non_existing_user");
        assertTrue(permissionMap.isEmpty());
    }

    @Test
    public void testGetPermissionMapForExistingUser() {
        LinkedHashMap<String, EnumSet<Permission>> permissionMap = propertiesRetriever.getPermissionMapForUser("username");
        Iterator<Map.Entry<String, EnumSet<Permission>>> iterator = permissionMap.entrySet().iterator();

        assertEquals(permissionMap.size(), 2);
        Map.Entry<String, EnumSet<Permission>> first = iterator.next();

        assertEquals(first.getKey(), "/cassandra/keyspaces/test");
        assertEquals(first.getValue(), EnumSet.of(Permission.READ, Permission.WRITE));
        Map.Entry<String, EnumSet<Permission>> second = iterator.next();

        assertEquals(second.getKey(), "/cassandra/keyspaces/test2");
        assertEquals(second.getValue(), EnumSet.of(Permission.READ));
    }

    @Test
    public void testGetGrantMapForNonExistingUser() {
        LinkedHashMap<String, EnumSet<Permission>> grantMap = propertiesRetriever.getGrantMapForUser("non_existing_user");
        assertTrue(grantMap.isEmpty());
    }

    @Test
    public void testGetGrantMapForExistingUser() {
        LinkedHashMap<String, EnumSet<Permission>> grantMap = propertiesRetriever.getGrantMapForUser("username");
        Iterator<Map.Entry<String, EnumSet<Permission>>> iterator = grantMap.entrySet().iterator();

        assertEquals(2, grantMap.size());
        Map.Entry<String, EnumSet<Permission>> first = iterator.next();

        assertEquals(first.getKey(), "/cassandra/keyspaces/test");
        assertEquals(first.getValue(), EnumSet.of(Permission.READ, Permission.WRITE));

        Map.Entry<String, EnumSet<Permission>> second = iterator.next();

        assertEquals(second.getKey(), "/cassandra/keyspaces/test2");
        assertEquals(second.getValue(), EnumSet.noneOf(Permission.class));
    }

    /*
    @Test
    public void testStorePermissionAddingEntry() throws Exception {
        String copiedFile = "src/test/resources/authorization_copy.properties";
        AuthorizerTest.copyFile(new File(System.getProperty(PropertiesAuthorizationBackend.AUTHORIZATION_FILENAME_PROPERTY)),
                 new File(copiedFile));
        System.setProperty(PropertiesAuthorizationBackend.AUTHORIZATION_FILENAME_PROPERTY, copiedFile);

        EnumSet<Permission> permission = EnumSet.of(Permission.SELECT, Permission.UPDATE);
        EnumSet<Permission> grant      = EnumSet.of(Permission.SELECT);

        assertTrue(propertiesRetriever.storePermission("username", "/cassandra/keyspaces/test3", permission, grant));

        LinkedHashMap<String, EnumSet<Permission>> permissionMap = propertiesRetriever.getPermissionMapForUser("username");
        LinkedHashMap<String, EnumSet<Permission>> grantMap = propertiesRetriever.getGrantMapForUser("username");

        assertEquals(3, permissionMap.size());
        assertEquals(3, grantMap.size());

        Iterator<Map.Entry<String, EnumSet<Permission>>> iteratorPerm = permissionMap.entrySet().iterator();
        Iterator<Map.Entry<String, EnumSet<Permission>>> iteratorGrant = grantMap.entrySet().iterator();

        Map.Entry<String, EnumSet<Permission>> firstPerm = iteratorPerm.next();
        assertEquals(firstPerm.getKey(), "/cassandra/keyspaces/test");
        assertEquals(firstPerm.getValue(), EnumSet.of(Permission.ALTER, Permission.CREATE, Permission.READ, Permission.WRITE));

        Map.Entry<String, EnumSet<Permission>> firstGrant = iteratorGrant.next();
        assertEquals(firstGrant.getKey(), "/cassandra/keyspaces/test");
        assertEquals(firstGrant.getValue(), EnumSet.of(Permission.READ, Permission.WRITE));

        Map.Entry<String, EnumSet<Permission>> secondPerm = iteratorPerm.next();
        assertEquals(secondPerm.getKey(), "/cassandra/keyspaces/test2");
        assertEquals(secondPerm.getValue(), EnumSet.of(Permission.READ));

        Map.Entry<String, EnumSet<Permission>> secondGrant = iteratorGrant.next();
        assertEquals(secondGrant.getKey(), "/cassandra/keyspaces/test2");
        assertEquals(secondGrant.getValue(), EnumSet.noneOf(Permission.class));

        Map.Entry<String, EnumSet<Permission>> thirdPerm = iteratorPerm.next();
        assertEquals(thirdPerm.getKey(), "/cassandra/keyspaces/test3");
        assertEquals(thirdPerm.getValue(), EnumSet.of(Permission.SELECT, Permission.UPDATE));

        Map.Entry<String, EnumSet<Permission>> thirdGrant = iteratorGrant.next();
        assertEquals(thirdGrant.getKey(), "/cassandra/keyspaces/test3");
        assertEquals(thirdGrant.getValue(), EnumSet.of(Permission.SELECT));
    }

    @Test
    public void testStorePermissionOverwritingEntry() throws Exception {
        String copiedFile = "src/test/resources/authorization_copy.properties";
        AuthorizerTest.copyFile(new File(System.getProperty(PropertiesAuthorizationBackend.AUTHORIZATION_FILENAME_PROPERTY)),
                 new File(copiedFile));
        System.setProperty(PropertiesAuthorizationBackend.AUTHORIZATION_FILENAME_PROPERTY, copiedFile);

        EnumSet<Permission> permission = EnumSet.of(Permission.SELECT, Permission.UPDATE);
        EnumSet<Permission> grant      = EnumSet.of(Permission.SELECT);

        assertTrue(propertiesRetriever.storePermission("username", "/cassandra/keyspaces/test", permission, grant));

        LinkedHashMap<String, EnumSet<Permission>> permissionMap = propertiesRetriever.getPermissionMapForUser("username");
        LinkedHashMap<String, EnumSet<Permission>> grantMap = propertiesRetriever.getGrantMapForUser("username");

        assertEquals(2, permissionMap.size());
        assertEquals(2, grantMap.size());

        Iterator<Map.Entry<String, EnumSet<Permission>>> iteratorPerm = permissionMap.entrySet().iterator();
        Iterator<Map.Entry<String, EnumSet<Permission>>> iteratorGrant = grantMap.entrySet().iterator();

        Map.Entry<String, EnumSet<Permission>> firstPerm = iteratorPerm.next();
        assertEquals(firstPerm.getKey(), "/cassandra/keyspaces/test");
        assertEquals(firstPerm.getValue(), EnumSet.of(Permission.SELECT, Permission.UPDATE));

        Map.Entry<String, EnumSet<Permission>> firstGrant = iteratorGrant.next();
        assertEquals(firstGrant.getKey(), "/cassandra/keyspaces/test");
        assertEquals(firstGrant.getValue(), EnumSet.of(Permission.SELECT));

        Map.Entry<String, EnumSet<Permission>> secondPerm = iteratorPerm.next();
        assertEquals(secondPerm.getKey(), "/cassandra/keyspaces/test2");
        assertEquals(secondPerm.getValue(), EnumSet.of(Permission.READ));

        Map.Entry<String, EnumSet<Permission>> secondGrant = iteratorGrant.next();
        assertEquals(secondGrant.getKey(), "/cassandra/keyspaces/test2");
        assertEquals(secondGrant.getValue(), EnumSet.noneOf(Permission.class));
    }
    */

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
         System.clearProperty(PropertiesAuthorizationBackend.AUTHORIZATION_FILENAME_PROPERTY);
         propertiesRetriever.validateBackend();
    }

    @Test
    public void testValidateBackendWithoutFile() throws Exception {
         exceptionExpectation.expect(ConfigurationException.class);
         System.setProperty(PropertiesAuthorizationBackend.AUTHORIZATION_FILENAME_PROPERTY, "non_existing");
         propertiesRetriever.validateBackend();
    }
}