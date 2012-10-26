package com.nedap.soul.cassandra.auth.helper;

import com.nedap.soul.cassandra.auth.authorization.CassandraAuthorizationBackend;
import com.nedap.soul.cassandra.auth.password.CassandraPasswordBackend;
import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import org.apache.cassandra.config.CFMetaData;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.KSMetaData;
import org.apache.cassandra.config.Schema;
import org.apache.cassandra.db.ColumnFamilyType;
import org.apache.cassandra.db.marshal.UTF8Type;
import org.apache.cassandra.io.util.FileUtils;
import org.apache.cassandra.locator.LocalStrategy;
import org.apache.cassandra.service.EmbeddedCassandraService;

public class CassandraHelper {

    private static EmbeddedCassandraService cassandra;


    private static final CFMetaData cfAuth = new CFMetaData(CassandraAuthorizationBackend.KEYSPACE,
                                                            CassandraAuthorizationBackend.COLUMN_FAMILY,
                                                            ColumnFamilyType.Standard,
                                                            UTF8Type.instance,
                                                            UTF8Type.instance);

    private static final CFMetaData cfPasswd = new CFMetaData(CassandraPasswordBackend.KEYSPACE,
                                                              CassandraPasswordBackend.COLUMN_FAMILY,
                                                              ColumnFamilyType.Standard,
                                                              UTF8Type.instance,
                                                              UTF8Type.instance);

    private static final KSMetaData ks = KSMetaData.newKeyspace(CassandraAuthorizationBackend.KEYSPACE,
                                                                    LocalStrategy.class, new HashMap<String, String>(),
                                                                    true, Arrays.asList(new CFMetaData[]{cfAuth, cfPasswd}));

    public static synchronized void startEmbeddedService() throws Exception {
        if(cassandra == null) {
            for (String s : DatabaseDescriptor.getAllDataFileLocations()) {
                File f = new File(s);
                if(f.exists()) {
                    FileUtils.deleteRecursive(f);
                }
            }
            File f = new File(DatabaseDescriptor.getCommitLogLocation());
            if(f.exists()) {
                FileUtils.deleteRecursive(f);
            }
            cassandra = new EmbeddedCassandraService();
            cassandra.start();
            Schema.instance.load(ks);
        }
    }
}
