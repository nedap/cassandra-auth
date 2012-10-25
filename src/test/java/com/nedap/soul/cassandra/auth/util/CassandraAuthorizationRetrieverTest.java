package com.nedap.soul.cassandra.auth.util;

import com.nedap.soul.cassandra.auth.helper.CassandraHelper;
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

public class CassandraAuthorizationRetrieverTest {

    @Rule
    public ExpectedException exceptionExpectation = ExpectedException.none();

    private final CassandraAuthorizationRetriever cassandraRetriever;

    public CassandraAuthorizationRetrieverTest() throws Exception {
        cassandraRetriever = new CassandraAuthorizationRetriever();
    }

    @BeforeClass
    public static void beforeClass() throws Exception {
        CassandraHelper.startEmbeddedService();

        EnumSetEncoder<Permission> encoder = new EnumSetEncoder<Permission>(Permission.class);

        RowMutation change = new RowMutation(CassandraAuthorizationRetriever.KEYSPACE, ByteBufferUtil.bytes(("username")));
        ColumnPath cpTest  = new ColumnPath(CassandraAuthorizationRetriever.COLUMN_FAMILY).setColumn(("/cassandra/keyspaces/test").getBytes());
        ColumnPath cpTest2 = new ColumnPath(CassandraAuthorizationRetriever.COLUMN_FAMILY).setColumn(("/cassandra/keyspaces/test2").getBytes());

        EnumSet<Permission> perms = EnumSet.of(Permission.ALTER, Permission.CREATE, Permission.READ, Permission.WRITE);
        EnumSet<Permission> perms2 = EnumSet.of(Permission.READ);

        change.add(new QueryPath(cpTest), ByteBufferUtil.bytes(encoder.encodeLong(perms)), 0);
        change.add(new QueryPath(cpTest2), ByteBufferUtil.bytes(encoder.encodeLong(perms2)), 0);
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
    public void testValidateBackendWithFile() throws Exception {
        try {
            cassandraRetriever.validateBackend();
        } catch(Exception e) {
            fail("No exception should be raised: " + e.getMessage());
        }
    }

}