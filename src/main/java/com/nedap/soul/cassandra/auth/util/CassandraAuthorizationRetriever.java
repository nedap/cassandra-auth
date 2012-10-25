package com.nedap.soul.cassandra.auth.util;

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
import org.apache.cassandra.db.SliceFromReadCommand;
import org.apache.cassandra.db.filter.QueryPath;
import org.apache.cassandra.service.StorageProxy;
import org.apache.cassandra.thrift.ConsistencyLevel;
import org.apache.cassandra.thrift.InvalidRequestException;
import org.apache.cassandra.thrift.UnavailableException;
import org.apache.cassandra.utils.ByteBufferUtil;

public class CassandraAuthorizationRetriever implements AuthorizationRetriever {
    public static final String KEYSPACE      = "access";
    public static final String COLUMN_FAMILY = "permissions";

    private static final EnumSetEncoder<Permission> encoder = new EnumSetEncoder<Permission>(Permission.class);

    @Override
    public LinkedHashMap<String, EnumSet<Permission>> getPermissionMapForUser(String username) {
        return getGrantAwarePermissionMapForUser(username, false);
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
            return result;
        } catch (UnavailableException ex) {
            return result;
        } catch (TimeoutException ex) {
            return result;
        } catch (InvalidRequestException ex) {
            return result;
        }
    }

    @Override
    public void validateBackend() throws ConfigurationException {
        CFMetaData cfMetaData = Schema.instance.getCFMetaData(KEYSPACE, COLUMN_FAMILY);
        if(cfMetaData == null) {
            String message = "Keyspace " + KEYSPACE + " and / or column family " + COLUMN_FAMILY + " not available";
            throw new ConfigurationException(message);
        }
    }



}