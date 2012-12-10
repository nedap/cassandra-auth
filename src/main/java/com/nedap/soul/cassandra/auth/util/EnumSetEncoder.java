package com.nedap.soul.cassandra.auth.util;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

public class EnumSetEncoder<E extends Enum<E>> {

    private final Map<Integer, E> ordinalMap;
    private Class<E> klass;

    public EnumSetEncoder(Class<E> klass) {
        ordinalMap = new HashMap<Integer, E>();
        this.klass = klass;
        for (E val : EnumSet.allOf(klass)) {
            ordinalMap.put(val.ordinal(), val);
        }
    }

    public EnumSet<E> decode(int value) {
        EnumSet<E> result = EnumSet.noneOf(klass);
        int ord = 0;
        int bit = 1;
        while(bit != 0) {
            if((value & bit) != 0) {
                E en = ordinalMap.get(ord);
                if(en != null) {
                    result.add(en);
                }
            }
            ++ord;
            bit <<= 1;
        }
        return result;
    }

    public int encode(EnumSet<E> perms) {
        int ret = 0;
        for(E p : perms) {
            ret |= (1 << p.ordinal());
        }
        return ret;
    }

}
