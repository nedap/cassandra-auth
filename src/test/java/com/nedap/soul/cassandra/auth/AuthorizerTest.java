package com.nedap.soul.cassandra.auth;

import com.nedap.soul.cassandra.auth.authorization.PropertiesAuthorizationBackend;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.Resources;
import org.apache.cassandra.config.ConfigurationException;
import org.apache.cassandra.cql3.CFName;
import org.apache.cassandra.thrift.Column;
import org.apache.cassandra.thrift.CqlResult;
import org.apache.cassandra.thrift.CqlRow;
import org.apache.cassandra.thrift.InvalidRequestException;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.ExpectedException;

public class AuthorizerTest {

    private Authorizer authorizer;

    @Rule
    public ExpectedException exceptionExpectation = ExpectedException.none();

    public AuthorizerTest() throws Exception {
        System.setProperty(PropertiesAuthorizationBackend.AUTHORIZATION_FILENAME_PROPERTY, "src/test/resources/authorization.properties");
        String copiedFile = "src/test/resources/authorization_copy.properties";
        AuthorizerTest.copyFile(new File(System.getProperty(PropertiesAuthorizationBackend.AUTHORIZATION_FILENAME_PROPERTY)),
                         new File(copiedFile));
        System.setProperty(PropertiesAuthorizationBackend.AUTHORIZATION_FILENAME_PROPERTY, copiedFile);
        authorizer = new Authorizer(new PropertiesAuthorizationBackend());
    }

    @Test
    public void testAuthorizeWithEmptyList() {
        assertEquals(authorizer.authorize(new AuthenticatedUser("username"), new ArrayList<Object>()), Permission.NONE);
    }

    @Test
    public void testAuthorizeWithSingleElementList() {
        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        assertEquals(authorizer.authorize(new AuthenticatedUser("username"), permissions), Permission.NONE);
    }

    @Test
    public void testAuthorizeWithMultipleElementListWithWrongEntries() {
        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        permissions.add(Resources.ROOT);
        assertEquals(authorizer.authorize(new AuthenticatedUser("username"), permissions), Permission.NONE);
    }

    @Test
    public void testAuthorizeWithoutUser() {
        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        permissions.add(Resources.KEYSPACES);
        assertEquals(authorizer.authorize(new AuthenticatedUser("username"), permissions), Permission.NONE);
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
        assertEquals(EnumSet.of(Permission.READ, Permission.WRITE),
                     authorizer.authorize(new AuthenticatedUser("username"), permissions));
    }

    @Test
    public void testAuthorizeWithValidUserForDeeperAccessiblePath() {
        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        permissions.add(Resources.KEYSPACES);
        permissions.add("test");
        permissions.add("deeper");
        assertEquals(EnumSet.of(Permission.READ, Permission.WRITE),
                     authorizer.authorize(new AuthenticatedUser("username"), permissions));
    }

    @Test
    public void testGrantWithNonExistingUser() throws Exception {
        exceptionExpectation.expect(InvalidRequestException.class);
        CFName cf = new CFName();
        cf.setKeyspace("test", true);

        authorizer.grant(new AuthenticatedUser("non_existing_user"), Permission.READ, "username_new", cf, false);
    }

    /*
    @Test
    public void testGrantWithUserWithoutRights() throws Exception {
        exceptionExpectation.expect(InvalidRequestException.class);
        CFName cf = new CFName();
        cf.setKeyspace("test", true);

        authorizer.grant(new AuthenticatedUser("username"), Permission.DESCRIBE, "username_new", cf, false);
    }

    @Test
    public void testGrantWithUserWithRightButNoGrant() throws Exception {
        exceptionExpectation.expect(InvalidRequestException.class);
        CFName cf = new CFName();
        cf.setKeyspace("test", true);

        authorizer.grant(new AuthenticatedUser("username"), Permission.ALTER, "username_new", cf, false);
    }

    @Test
    public void testGrantWithUserWithRightAndGrant() throws Exception {
        CFName cf = new CFName();
        cf.setKeyspace("test", true);
        authorizer.grant(new AuthenticatedUser("username"), Permission.READ, "username_new", cf, false);

        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        permissions.add(Resources.KEYSPACES);
        permissions.add(cf.getKeyspace());

        assertEquals(EnumSet.of(Permission.READ), authorizer.authorize(new AuthenticatedUser("username_new"), permissions));
    }

    @Test
    public void testGrantWithUserWithRightAndGrantNotCascadingGrantRight() throws Exception {
        exceptionExpectation.expect(InvalidRequestException.class);

        CFName cf = new CFName();
        cf.setKeyspace("test", true);
        authorizer.grant(new AuthenticatedUser("username"), Permission.READ, "username_new", cf, false);
        authorizer.grant(new AuthenticatedUser("username_new"), Permission.READ, "username_newer", cf, false);
    }

    @Test
    public void testGrantWithUserWithRightAndGrantCascadingGrantRight() throws Exception {
        CFName cf = new CFName();
        cf.setKeyspace("test", true);
        authorizer.grant(new AuthenticatedUser("username"), Permission.READ, "username_new", cf, true);
        authorizer.grant(new AuthenticatedUser("username_new"), Permission.READ, "username_newer", cf, false);

        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        permissions.add(Resources.KEYSPACES);
        permissions.add(cf.getKeyspace());

        assertEquals(EnumSet.of(Permission.READ), authorizer.authorize(new AuthenticatedUser("username_newer"), permissions));
    }

    @Test
    public void testRevokeWithNonExistingUser() throws Exception {
        exceptionExpectation.expect(InvalidRequestException.class);
        CFName cf = new CFName();
        cf.setKeyspace("test", true);

        authorizer.revoke(new AuthenticatedUser("non_existing_user"), Permission.READ, "username_new", cf);
    }

    @Test
    public void testRevokeWithUserWithoutRights() throws Exception {
        exceptionExpectation.expect(InvalidRequestException.class);
        CFName cf = new CFName();
        cf.setKeyspace("test", true);

        authorizer.revoke(new AuthenticatedUser("username"), Permission.DROP, "username_new", cf);
    }

    @Test
    public void testRevokeWithUserWithRightButNoGrant() throws Exception {
        exceptionExpectation.expect(InvalidRequestException.class);
        CFName cf = new CFName();
        cf.setKeyspace("test", true);

        authorizer.revoke(new AuthenticatedUser("username"), Permission.ALTER, "username", cf);
    }

    @Test
    public void testRevokeWithUserWithRightAndGrant() throws Exception {
        CFName cf = new CFName();
        cf.setKeyspace("test", true);
        authorizer.revoke(new AuthenticatedUser("username"), Permission.WRITE, "username", cf);

        List<Object> permissions = new ArrayList<Object>();
        permissions.add(Resources.ROOT);
        permissions.add(Resources.KEYSPACES);
        permissions.add(cf.getKeyspace());

        assertEquals(EnumSet.of(Permission.CREATE, Permission.READ, Permission.ALTER),
                     authorizer.authorize(new AuthenticatedUser("username"), permissions));
    }
    */

    @Test
    public void testValidateConfigurationWithoutProperty() throws Exception {
        exceptionExpectation.expect(ConfigurationException.class);

        System.clearProperty(PropertiesAuthorizationBackend.AUTHORIZATION_FILENAME_PROPERTY);
        authorizer.validateConfiguration();
    }

    @Test
    public void testValidateConfigurationWithNonExistingPropertyFile() throws Exception {
        exceptionExpectation.expect(ConfigurationException.class);

        System.setProperty(PropertiesAuthorizationBackend.AUTHORIZATION_FILENAME_PROPERTY, "non_existing");
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
        assertEquals(2, row1.columns.size());
        Column colPerm1 = row1.columns.get(0);
        Column colGrant1 = row1.columns.get(1);
        assertEquals("permissions", ByteBufferUtil.string(colPerm1.name));
        assertEquals("[READ, WRITE]", ByteBufferUtil.string(colPerm1.value));
        assertEquals("grants", ByteBufferUtil.string(colGrant1.name));
        assertEquals("[READ, WRITE]", ByteBufferUtil.string(colGrant1.value));

        assertEquals("/cassandra/keyspaces/test2", ByteBufferUtil.string(row2.key));
        assertEquals(2, row2.columns.size());
        Column colPerm2 = row2.columns.get(0);
        Column colGrant2 = row2.columns.get(1);
        assertEquals("permissions", ByteBufferUtil.string(colPerm2.name));
        assertEquals("[READ]", ByteBufferUtil.string(colPerm2.value));
        assertEquals("grants", ByteBufferUtil.string(colGrant2.name));
        assertEquals("[]", ByteBufferUtil.string(colGrant2.value));
    }

    public static void copyFile(File sourceFile, File destFile) throws IOException {
        if(!destFile.exists()) {
            destFile.createNewFile();
        }

        FileChannel source = null;
        FileChannel destination = null;

        try {
            source = new FileInputStream(sourceFile).getChannel();
            destination = new FileOutputStream(destFile).getChannel();
            destination.transferFrom(source, 0, source.size());
        }
        finally {
            if(source != null) {
                source.close();
            }
            if(destination != null) {
                destination.close();
            }
        }
    }

}