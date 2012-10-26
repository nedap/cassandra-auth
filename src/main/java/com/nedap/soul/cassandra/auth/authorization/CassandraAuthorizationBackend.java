package com.nedap.soul.cassandra.auth.authorization;

import com.nedap.soul.cassandra.auth.util.EnumSetEncoder;
import java.io.IOException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.TimeoutException;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.config.CFMetaData;
import org.apache.cassandra.config.ConfigurationException;
import org.apache.cassandra.config.Schema;
import org.apache.cassandra.db.IColumn;
import org.apache.cassandra.db.ReadCommand;
import org.apache.cassandra.db.Row;
import org.apache.cassandra.db.RowMutation;
import org.apache.cassandra.db.SliceFromReadCommand;
import org.apache.cassandra.db.filter.QueryPath;
import org.apache.cassandra.service.StorageProxy;
import org.apache.cassandra.thrift.ColumnPath;
import org.apache.cassandra.thrift.ConsistencyLevel;
import org.apache.cassandra.thrift.InvalidRequestException;
import org.apache.cassandra.thrift.UnavailableException;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CassandraAuthorizationBackend implements AuthorizationBackend {
    public static final String KEYSPACE      = "access";
    public static final String COLUMN_FAMILY = "permissions";

    private static final EnumSetEncoder<Permission> encoder = new EnumSetEncoder<Permission>(Permission.class);
    private static Logger logger = LoggerFactory.getLogger(CassandraAuthorizationBackend.class);

    @Override
    public LinkedHashMap<String, EnumSet<Permission>> getPermissionMapForUser(String username) {
        return getGrantAwarePermissionMapForUser(username, false);
    }

    @Override
    public LinkedHashMap<String, EnumSet<Permission>> getGrantMapForUser(String username) {
        return getGrantAwarePermissionMapForUser(username, true);
    }

    @Override
    public void validateBackend() throws ConfigurationException {
        CFMetaData cfMetaData = Schema.instance.getCFMetaData(KEYSPACE, COLUMN_FAMILY);
        if(cfMetaData == null) {
            String message = "Keyspace " + KEYSPACE + " and / or column family " + COLUMN_FAMILY + " not available";
            throw new ConfigurationException(message);
        }
    }

    @Override
    public boolean storePermission(String username, String resource, EnumSet<Permission> perms, EnumSet<Permission> grants) {
        RowMutation change = new RowMutation(CassandraAuthorizationBackend.KEYSPACE, ByteBufferUtil.bytes(username));
        ColumnPath cp = new ColumnPath(CassandraAuthorizationBackend.COLUMN_FAMILY).setColumn(ByteBufferUtil.bytes(resource));

        long serialized = (long)encoder.encode(grants) << 32 | (long)encoder.encode(perms);
        change.add(new QueryPath(cp), ByteBufferUtil.bytes(serialized), 0);
        try {
            StorageProxy.mutate(Arrays.asList(change), ConsistencyLevel.ONE);
            return true;
        } catch (UnavailableException ex) {
            logger.error("Failed to store permissions", ex);
            return false;
        } catch (TimeoutException ex) {
            logger.error("Failed to store permissions", ex);
            return false;
        }
    }

    private LinkedHashMap<String, EnumSet<Permission>> getGrantAwarePermissionMapForUser(String username, boolean grants) {
        LinkedHashMap<String, EnumSet<Permission>> result = new LinkedHashMap<String, EnumSet<Permission>>();

        QueryPath path = new QueryPath(COLUMN_FAMILY);
        ReadCommand command = new SliceFromReadCommand(KEYSPACE, ByteBufferUtil.bytes(username),
                                                       path, ByteBufferUtil.EMPTY_BYTE_BUFFER,
                                                       ByteBufferUtil.EMPTY_BYTE_BUFFER, true, 1000);
        try {
            List<Row> read = StorageProxy.read(Arrays.asList(command), ConsistencyLevel.ONE);
            if(read.isEmpty()) {
                return null;
            }
            for(Row r: read) {
                if (r.cf != null) {
                    for (IColumn col : r.cf.getSortedColumns()) {
                        String entry = ByteBufferUtil.string(col.name());
                        long val = ByteBufferUtil.toLong(col.value());
                        if(grants) {
                            result.put(entry, encoder.decode((int)(val >> 32)));
                        } else {
                            result.put(entry, encoder.decode((int)val));
                        }
                    }
                }
            }
            return result;
        } catch (IOException ex) {
            logger.error("Failed to retrieve grant permissions", ex);
            return result;
        } catch (UnavailableException ex) {
            logger.error("Failed to retrieve grant permissions", ex);
            return result;
        } catch (TimeoutException ex) {
            logger.error("Failed to retrieve grant permissions", ex);
            return result;
        } catch (InvalidRequestException ex) {
            logger.error("Failed to retrieve grant permissions", ex);
            return result;
        }
    }
}