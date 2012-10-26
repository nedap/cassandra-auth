package com.nedap.soul.cassandra.auth.authorization;

import com.nedap.soul.cassandra.auth.helper.CassandraHelper;
import com.nedap.soul.cassandra.auth.util.EnumSetEncoder;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.db.RowMutation;
import org.apache.cassandra.db.filter.QueryPath;
import org.apache.cassandra.service.StorageProxy;
import org.apache.cassandra.thrift.ColumnPath;
import org.apache.cassandra.thrift.ConsistencyLevel;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.ExpectedException;

public class CassandraAuthorizationBackendTest {

    @Rule
    public ExpectedException exceptionExpectation = ExpectedException.none();

    private final CassandraAuthorizationBackend cassandraRetriever;

    public CassandraAuthorizationBackendTest() throws Exception {
        cassandraRetriever = new CassandraAuthorizationBackend();
    }

    @BeforeClass
    public static void beforeClass() throws Exception {
        CassandraHelper.startEmbeddedService();

        EnumSetEncoder<Permission> encoder = new EnumSetEncoder<Permission>(Permission.class);

        RowMutation change = new RowMutation(CassandraAuthorizationBackend.KEYSPACE, ByteBufferUtil.bytes(("username")));
        ColumnPath cpTest  = new ColumnPath(CassandraAuthorizationBackend.COLUMN_FAMILY).setColumn(("/cassandra/keyspaces/test").getBytes());
        ColumnPath cpTest2 = new ColumnPath(CassandraAuthorizationBackend.COLUMN_FAMILY).setColumn(("/cassandra/keyspaces/test2").getBytes());

        EnumSet<Permission> perms   = EnumSet.of(Permission.ALTER, Permission.CREATE, Permission.READ, Permission.WRITE);
        EnumSet<Permission> grants  = EnumSet.of(Permission.READ, Permission.WRITE);
        EnumSet<Permission> perms2  = EnumSet.of(Permission.READ);
        EnumSet<Permission> grants2 = EnumSet.noneOf(Permission.class);

        long serialized = (long)encoder.encode(grants) << 32 | (long)encoder.encode(perms);
        long serialized2 = (long)encoder.encode(grants2) << 32 | (long)encoder.encode(perms2);
        change.add(new QueryPath(cpTest), ByteBufferUtil.bytes(serialized), 0);
        change.add(new QueryPath(cpTest2), ByteBufferUtil.bytes(serialized2), 0);
        StorageProxy.mutate(Arrays.asList(change), ConsistencyLevel.ONE);
    }

    @Test
    public void testGetPermissionMapForNonExistingUser() {
        LinkedHashMap<String, EnumSet<Permission>> permissionMap = cassandraRetriever.getPermissionMapForUser("non_existing_user");
        assertTrue(permissionMap.isEmpty());
    }

    @Test
    public void testGetPermissionMapForExistingUser() {
        LinkedHashMap<String, EnumSet<Permission>> permissionMap = cassandraRetriever.getPermissionMapForUser("username");
        Iterator<Map.Entry<String, EnumSet<Permission>>> iterator = permissionMap.entrySet().iterator();

        assertEquals(permissionMap.size(), 2);
        Map.Entry<String, EnumSet<Permission>> first = iterator.next();

        assertEquals(first.getKey(), "/cassandra/keyspaces/test");
        assertEquals(first.getValue(), EnumSet.of(Permission.ALTER, Permission.CREATE, Permission.READ, Permission.WRITE));
        Map.Entry<String, EnumSet<Permission>> second = iterator.next();

        assertEquals(second.getKey(), "/cassandra/keyspaces/test2");
        assertEquals(second.getValue(), EnumSet.of(Permission.READ));
    }

    @Test
    public void testGetGrantMapForNonExistingUser() {
        LinkedHashMap<String, EnumSet<Permission>> permissionMap = cassandraRetriever.getGrantMapForUser("non_existing_user");
        assertTrue(permissionMap.isEmpty());
    }

    @Test
    public void testGetGrantMapForExistingUser() {
        LinkedHashMap<String, EnumSet<Permission>> permissionMap = cassandraRetriever.getGrantMapForUser("username");
        Iterator<Map.Entry<String, EnumSet<Permission>>> iterator = permissionMap.entrySet().iterator();

        assertEquals(2, permissionMap.size());
        Map.Entry<String, EnumSet<Permission>> first = iterator.next();

        assertEquals(first.getKey(), "/cassandra/keyspaces/test");
        assertEquals(first.getValue(), EnumSet.of(Permission.READ, Permission.WRITE));

        Map.Entry<String, EnumSet<Permission>> second = iterator.next();

        assertEquals(second.getKey(), "/cassandra/keyspaces/test2");
        assertEquals(second.getValue(), EnumSet.noneOf(Permission.class));
    }

    @Test
    public void testStorePermissionAddingEntry() throws Exception {

        EnumSet<Permission> permission = EnumSet.of(Permission.SELECT, Permission.UPDATE);
        EnumSet<Permission> grant      = EnumSet.of(Permission.SELECT);

        assertTrue(cassandraRetriever.storePermission("username2", "/cassandra/keyspaces/test3", permission, grant));

        LinkedHashMap<String, EnumSet<Permission>> permissionMap = cassandraRetriever.getPermissionMapForUser("username2");
        LinkedHashMap<String, EnumSet<Permission>> grantMap = cassandraRetriever.getGrantMapForUser("username2");

        assertEquals(1, permissionMap.size());
        assertEquals(1, grantMap.size());

        Iterator<Map.Entry<String, EnumSet<Permission>>> iteratorPerm = permissionMap.entrySet().iterator();
        Iterator<Map.Entry<String, EnumSet<Permission>>> iteratorGrant = grantMap.entrySet().iterator();

        Map.Entry<String, EnumSet<Permission>> firstPerm = iteratorPerm.next();
        assertEquals(firstPerm.getKey(), "/cassandra/keyspaces/test3");
        assertEquals(firstPerm.getValue(), EnumSet.of(Permission.SELECT, Permission.UPDATE));

        Map.Entry<String, EnumSet<Permission>> firstGrant = iteratorGrant.next();
        assertEquals(firstGrant.getKey(), "/cassandra/keyspaces/test3");
        assertEquals(firstGrant.getValue(), EnumSet.of(Permission.SELECT));
    }

    @Test
    public void testValidateBackendWithFile() throws Exception {
        try {
            cassandraRetriever.validateBackend();
        } catch(Exception e) {
            fail("No exception should be raised: " + e.getMessage());
        }
    }

}