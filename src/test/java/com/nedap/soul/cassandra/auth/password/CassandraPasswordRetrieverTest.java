package com.nedap.soul.cassandra.auth.password;

import com.nedap.soul.cassandra.auth.helper.CassandraHelper;
import java.util.Arrays;
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

public class CassandraPasswordRetrieverTest {

    @Rule
    public ExpectedException exceptionExpectation = ExpectedException.none();

    private final CassandraPasswordBackend propertiesRetriever;

    public CassandraPasswordRetrieverTest() throws Exception {
        propertiesRetriever = new CassandraPasswordBackend();
    }

    @BeforeClass
    public static void beforeClass() throws Exception {
        CassandraHelper.startEmbeddedService();

        RowMutation change = new RowMutation(CassandraPasswordBackend.KEYSPACE, ByteBufferUtil.bytes(("username")));
        ColumnPath cp = new ColumnPath(CassandraPasswordBackend.COLUMN_FAMILY).setColumn(("password").getBytes());
        change.add(new QueryPath(cp), ByteBufferUtil.bytes(("65536:256:66697865645f73616c74:a7da14d5955d903dfba9f6bc0ba403e518e27f66364080e4d16e5fcf72fe8983")), 0);
        StorageProxy.mutate(Arrays.asList(change), ConsistencyLevel.ONE);
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

}