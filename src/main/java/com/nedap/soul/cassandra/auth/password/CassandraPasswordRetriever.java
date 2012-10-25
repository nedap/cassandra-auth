package com.nedap.soul.cassandra.auth.password;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeoutException;
import org.apache.cassandra.config.CFMetaData;
import org.apache.cassandra.config.ConfigurationException;
import org.apache.cassandra.config.Schema;
import org.apache.cassandra.db.IColumn;
import org.apache.cassandra.db.ReadCommand;
import org.apache.cassandra.db.Row;
import org.apache.cassandra.db.SliceByNamesReadCommand;
import org.apache.cassandra.db.filter.QueryPath;
import org.apache.cassandra.service.StorageProxy;
import org.apache.cassandra.thrift.ConsistencyLevel;
import org.apache.cassandra.thrift.InvalidRequestException;
import org.apache.cassandra.thrift.UnavailableException;
import org.apache.cassandra.utils.ByteBufferUtil;

public class CassandraPasswordRetriever implements PasswordRetriever {

    public static final String KEYSPACE      = "access";
    public static final String COLUMN_FAMILY = "users";

    @Override
    public String getPasswordHashForUser(String username, String field) {
        QueryPath path = new QueryPath(COLUMN_FAMILY);
        ReadCommand command = new SliceByNamesReadCommand(KEYSPACE, ByteBufferUtil.bytes(username),
                                                          path, Arrays.asList(ByteBufferUtil.bytes(field)));
        try {
            List<Row> read = StorageProxy.read(Arrays.asList(command), ConsistencyLevel.ONE);
            if(read.isEmpty()) {
                return null;
            }
            for(Row r: read) {
                if (r.cf != null) {
                    for (IColumn col : r.cf.getSortedColumns()) {
                        return ByteBufferUtil.string(col.value());
                    }
                }
            }
            return null;
        } catch (IOException ex) {
            return null;
        } catch (UnavailableException ex) {
            return null;
        } catch (TimeoutException ex) {
            return null;
        } catch (InvalidRequestException ex) {
            return null;
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