package org.apache.cassandra.locator;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.cassandra.config.ConfigurationException;

import org.apache.cassandra.dht.Token;
import org.apache.cassandra.gms.Gossiper;

public class AllNodeStrategy extends AbstractReplicationStrategy
{
    public AllNodeStrategy(String table, TokenMetadata tokenMetadata, IEndpointSnitch snitch, Map<String, String> configOptions) {
        super(table, tokenMetadata, snitch, configOptions);
    }

    @Override
    public List<InetAddress> calculateNaturalEndpoints(Token token, TokenMetadata metadata) {
        Set<InetAddress> allMembers = Gossiper.instance.getLiveMembers();
        allMembers.addAll(Gossiper.instance.getUnreachableMembers());
        return new ArrayList(allMembers);
    }

    @Override
    public int getReplicationFactor() {
        return Gossiper.instance.getLiveMembers().size() +
               Gossiper.instance.getUnreachableMembers().size();
    }

    @Override
    public void validateOptions() throws ConfigurationException {
    }

}
