package com.nedap.soul.cassandra.auth;

import com.nedap.soul.cassandra.auth.util.PropertiesAuthorizationRetriever;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.Resources;
import org.apache.cassandra.config.ConfigurationException;
import org.apache.cassandra.thrift.Column;
import org.apache.cassandra.thrift.CqlResult;
import org.apache.cassandra.thrift.CqlRow;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.ExpectedException;

public class AuthorizerTest {

    private Authorizer authorizer;

    @Rule
    public ExpectedException exceptionExpectation = ExpectedException.none();

    public AuthorizerTest() {
        System.setProperty(PropertiesAuthorizationRetriever.AUTHORIZATION_FILENAME_PROPERTY, "src/test/resources/authorization.properties");
        authorizer = new Authorizer(new PropertiesAuthorizationRetriever());
    }

    @Test
    public void testAuthorizeWithEmptyList() {
        assertEquals(authorizer.authorize(null, new ArrayList<Object>()), Permission.NONE);
    }

    @Test
    public void testAuthorizeWithSingleElementList() {
        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        assertEquals(authorizer.authorize(null, permissions), Permission.NONE);
    }

    @Test
    public void testAuthorizeWithMultipleElementListWithWrongEntries() {
        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        permissions.add(Resources.ROOT);
        assertEquals(authorizer.authorize(null, permissions), Permission.NONE);
    }

    @Test
    public void testAuthorizeWithoutUser() {
        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        permissions.add(Resources.KEYSPACES);
        assertEquals(authorizer.authorize(null, permissions), Permission.NONE);
    }

    @Test
    public void testAuthorizeWithInvalidUser() {
        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        permissions.add(Resources.KEYSPACES);
        assertEquals(authorizer.authorize(new AuthenticatedUser("non_existant_user"), permissions), Permission.NONE);
    }

    @Test
    public void testAuthorizeWithValidUserForNonAccessiblePath() {
        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        permissions.add(Resources.KEYSPACES);
        assertEquals(authorizer.authorize(new AuthenticatedUser("username"), permissions), Permission.NONE);
    }

    @Test
    public void testAuthorizeWithValidUserForAccessiblePath() {
        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        permissions.add(Resources.KEYSPACES);
        permissions.add("test");
        assertEquals(authorizer.authorize(new AuthenticatedUser("username"), permissions), EnumSet.of(Permission.ALTER, Permission.CREATE, Permission.READ, Permission.WRITE));
    }

    @Test
    public void testAuthorizeWithValidUserForDeeperAccessiblePath() {
        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        permissions.add(Resources.KEYSPACES);
        permissions.add("test");
        permissions.add("deeper");
        assertEquals(authorizer.authorize(new AuthenticatedUser("username"), permissions), EnumSet.of(Permission.ALTER, Permission.CREATE, Permission.READ, Permission.WRITE));
    }

    @Test
    public void testValidateConfigurationWithoutProperty() throws Exception {
        exceptionExpectation.expect(ConfigurationException.class);

        System.clearProperty(PropertiesAuthorizationRetriever.AUTHORIZATION_FILENAME_PROPERTY);
        authorizer.validateConfiguration();
    }

    @Test
    public void testValidateConfigurationWithNonExistingPropertyFile() throws Exception {
        exceptionExpectation.expect(ConfigurationException.class);

        System.setProperty(PropertiesAuthorizationRetriever.AUTHORIZATION_FILENAME_PROPERTY, "non_existing");
        authorizer.validateConfiguration();
    }

    @Test
    public void testValidateConfigurationWithExistingPropertyFile() throws Exception {
        try {
            authorizer.validateConfiguration();
        } catch (ConfigurationException e) {
            fail("configuration exception thrown: "+ e.getMessage());
        }
    }

    @Test
    public void testListPermissions() throws Exception {
        CqlResult listPermissions = authorizer.listPermissions("username");
        assertEquals(2, listPermissions.num);
        assertEquals(2, listPermissions.rows.size());
        CqlRow row1 = listPermissions.rows.get(0);
        CqlRow row2 = listPermissions.rows.get(1);

        assertEquals("/cassandra/keyspaces/test", ByteBufferUtil.string(row1.key));
        assertEquals(1, row1.columns.size());
        Column col1 = row1.columns.get(0);
        assertEquals("permissions", ByteBufferUtil.string(col1.name));
        assertEquals("[READ, WRITE, CREATE, ALTER]", ByteBufferUtil.string(col1.value));

        assertEquals("/cassandra/keyspaces/test2", ByteBufferUtil.string(row2.key));
        assertEquals(1, row2.columns.size());
        Column col2 = row2.columns.get(0);
        assertEquals("permissions", ByteBufferUtil.string(col2.name));
        assertEquals("[READ]", ByteBufferUtil.string(col2.value));
    }
}